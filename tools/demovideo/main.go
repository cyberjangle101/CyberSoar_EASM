// Command demovideo assembles the demo video from the PNG frames tools/democap captured:
// an MJPEG AVI at full size for YouTube and other video sites, and a small animated GIF for the
// README. It uses only the standard library, so making the video needs no encoder installed.
//
//	go run ./tools/demovideo -frames <dir> -story docs/demo/storyboard.txt -avi demo.avi -gif docs/images/demo.gif
//
// Each storyboard line is one scene:
//
//	hold <name> <seconds>          one still frame, <name>.png
//	play <prefix> <seconds>        the frames <prefix>-000.png, -001.png ..., spread over the time
//	fade <seconds>                 cross-fade from the previous scene into the next one
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// scene is a run of output frames: still or moving, then an optional fade into the next.
type scene struct {
	frames []*image.RGBA // the source frames, played evenly over secs
	secs   float64
	fade   float64 // cross-fade into the next scene
}

func main() {
	dir := flag.String("frames", "", "folder with the captured PNG frames")
	story := flag.String("story", "docs/demo/storyboard.txt", "the scenes")
	aviOut := flag.String("avi", "", "write the MJPEG AVI here")
	gifOut := flag.String("gif", "", "write the README GIF here")
	fps := flag.Int("fps", 15, "AVI frame rate")
	gifWidth := flag.Int("gif-width", 960, "GIF width")
	gifFPS := flag.Int("gif-fps", 5, "GIF frame rate for moving scenes")
	flag.Parse()
	scenes, err := load(*dir, *story)
	if err != nil {
		log.Fatal(err)
	}
	if *aviOut != "" {
		if err := writeAVI(*aviOut, scenes, *fps); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote", *aviOut)
	}
	if *gifOut != "" {
		if err := writeGIF(*gifOut, scenes, *gifWidth, *gifFPS); err != nil {
			log.Fatal(err)
		}
		fmt.Println("wrote", *gifOut)
	}
}

func load(dir, story string) ([]*scene, error) {
	f, err := os.Open(story)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []*scene
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.Fields(sc.Text())
		if len(w) == 0 || strings.HasPrefix(w[0], "#") {
			continue
		}
		num := func(i int) float64 {
			if i >= len(w) {
				return 0
			}
			v, _ := strconv.ParseFloat(w[i], 64)
			return v
		}
		switch w[0] {
		case "hold":
			img, err := readPNG(filepath.Join(dir, w[1]+".png"))
			if err != nil {
				return nil, err
			}
			out = append(out, &scene{frames: []*image.RGBA{img}, secs: num(2)})
		case "play":
			names, _ := filepath.Glob(filepath.Join(dir, w[1]+"-[0-9][0-9][0-9].png"))
			sort.Strings(names)
			if len(names) == 0 {
				return nil, fmt.Errorf("no frames for %s", w[1])
			}
			s := &scene{secs: num(2)}
			for _, n := range names {
				img, err := readPNG(n)
				if err != nil {
					return nil, err
				}
				s.frames = append(s.frames, img)
			}
			out = append(out, s)
		case "fade":
			if len(out) == 0 {
				return nil, errors.New("fade before the first scene")
			}
			out[len(out)-1].fade = num(1)
		default:
			return nil, fmt.Errorf("unknown storyboard step %q", w[0])
		}
	}
	return out, sc.Err()
}

func readPNG(path string) (*image.RGBA, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	img, err := png.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	b := img.Bounds()
	rgba := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			rgba.Set(x, y, img.At(b.Min.X+x, b.Min.Y+y))
		}
	}
	return rgba, nil
}

// at is the scene's source frame at fraction t (0..1) of its time.
func (s *scene) at(t float64) *image.RGBA {
	i := int(t * float64(len(s.frames)))
	return s.frames[min(max(i, 0), len(s.frames)-1)]
}

// blend mixes a and b, k=0 is a, k=1 is b.
func blend(a, b *image.RGBA, k float64) *image.RGBA {
	out := image.NewRGBA(a.Rect)
	ka, kb := 1-k, k
	for i := range out.Pix {
		out.Pix[i] = uint8(float64(a.Pix[i])*ka + float64(b.Pix[i])*kb + 0.5)
	}
	return out
}

// timeline calls emit for every output frame at the given rate.
func timeline(scenes []*scene, fps int, emit func(*image.RGBA) error) error {
	for i, s := range scenes {
		n := max(int(s.secs*float64(fps)+0.5), 1)
		for f := 0; f < n; f++ {
			if err := emit(s.at(float64(f) / float64(n))); err != nil {
				return err
			}
		}
		if s.fade > 0 && i+1 < len(scenes) {
			nf := max(int(s.fade*float64(fps)+0.5), 1)
			from, to := s.frames[len(s.frames)-1], scenes[i+1].frames[0]
			for f := 1; f <= nf; f++ {
				if err := emit(blend(from, to, float64(f)/float64(nf+1))); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ---- AVI with Motion-JPEG frames (RIFF AVI 1.0, one video stream, an idx1 index)

func writeAVI(path string, scenes []*scene, fps int) error {
	var w, h int
	if len(scenes) > 0 {
		w, h = scenes[0].frames[0].Rect.Dx(), scenes[0].frames[0].Rect.Dy()
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	le := func(v ...any) {
		for _, x := range v {
			_ = binary.Write(f, binary.LittleEndian, x)
		}
	}
	fourcc := func(s string) { _, _ = io.WriteString(f, s) }

	fourcc("RIFF")
	le(uint32(0)) // patched
	fourcc("AVI ")
	fourcc("LIST")
	le(uint32(4 + 8 + 56 + 8 + 4 + 8 + 56 + 8 + 40))
	fourcc("hdrl")
	fourcc("avih")
	le(uint32(56))
	framesAt, _ := f.Seek(0, io.SeekCurrent)
	le(uint32(1000000/fps), uint32(0), uint32(0), uint32(0x10), uint32(0), uint32(0), uint32(1), uint32(0), uint32(w), uint32(h),
		uint32(0), uint32(0), uint32(0), uint32(0))
	fourcc("LIST")
	le(uint32(4 + 8 + 56 + 8 + 40))
	fourcc("strl")
	fourcc("strh")
	le(uint32(56))
	fourcc("vids")
	fourcc("MJPG")
	le(uint32(0), uint16(0), uint16(0), uint32(0), uint32(1), uint32(fps), uint32(0))
	lengthAt, _ := f.Seek(0, io.SeekCurrent)
	le(uint32(0), uint32(0), int32(-1), uint32(0), int16(0), int16(0), int16(w), int16(h))
	fourcc("strf")
	le(uint32(40), int32(w), int32(h), uint16(1), uint16(24))
	fourcc("MJPG")
	le(uint32(w*h*3), int32(0), int32(0), uint32(0), uint32(0))
	fourcc("LIST")
	moviSizeAt, _ := f.Seek(0, io.SeekCurrent)
	le(uint32(0))
	moviAt, _ := f.Seek(0, io.SeekCurrent)
	fourcc("movi")

	type entry struct{ off, size uint32 }
	var index []entry
	var maxSize uint32
	err = timeline(scenes, fps, func(img *image.RGBA) error {
		var jb jpegBuf
		if err := jpeg.Encode(&jb, img, &jpeg.Options{Quality: 88}); err != nil {
			return err
		}
		pos, _ := f.Seek(0, io.SeekCurrent)
		fourcc("00dc")
		le(uint32(len(jb)))
		if _, err := f.Write(jb); err != nil {
			return err
		}
		if len(jb)%2 == 1 {
			_, _ = f.Write([]byte{0})
		}
		index = append(index, entry{uint32(pos - moviAt), uint32(len(jb))})
		maxSize = max(maxSize, uint32(len(jb)))
		return nil
	})
	if err != nil {
		return err
	}
	end, _ := f.Seek(0, io.SeekCurrent)
	fourcc("idx1")
	le(uint32(16 * len(index)))
	for _, e := range index {
		fourcc("00dc")
		le(uint32(0x10), e.off, e.size)
	}
	total, _ := f.Seek(0, io.SeekCurrent)

	patch := func(at int64, v ...any) {
		_, _ = f.Seek(at, io.SeekStart)
		le(v...)
	}
	patch(4, uint32(total-8))
	patch(moviSizeAt, uint32(end-moviAt))
	patch(framesAt+16, uint32(len(index)))       // dwTotalFrames
	patch(framesAt+28, maxSize)                  // dwSuggestedBufferSize
	patch(lengthAt, uint32(len(index)), maxSize) // strh dwLength, dwSuggestedBufferSize
	return nil
}

type jpegBuf []byte

func (b *jpegBuf) Write(p []byte) (int, error) { *b = append(*b, p...); return len(p), nil }

// ---- the README GIF: smaller, one shared palette, held scenes stored once with a long delay

func writeGIF(path string, scenes []*scene, width, fps int) error {
	type frame struct {
		img   *image.RGBA
		delay int // hundredths of a second
	}
	var frames []frame
	add := func(img *image.RGBA, secs float64) {
		frames = append(frames, frame{scale(img, width), max(int(secs*100+0.5), 2)})
	}
	for i, s := range scenes {
		if len(s.frames) == 1 {
			add(s.frames[0], s.secs)
		} else {
			n := max(int(s.secs*float64(fps)+0.5), 1)
			for f := 0; f < n; f++ {
				add(s.at(float64(f)/float64(n)), 1/float64(fps))
			}
		}
		if s.fade > 0 && i+1 < len(scenes) {
			from, to := s.frames[len(s.frames)-1], scenes[i+1].frames[0]
			for f := 1; f <= 3; f++ {
				add(blend(from, to, float64(f)/4), s.fade/3)
			}
		}
	}
	var all []*image.RGBA
	for _, f := range frames {
		all = append(all, f.img)
	}
	pal := medianCut(all, 256)
	g := &gif.GIF{LoopCount: 0}
	for _, f := range frames {
		p := image.NewPaletted(f.img.Rect, pal)
		for y := 0; y < f.img.Rect.Dy(); y++ {
			for x := 0; x < f.img.Rect.Dx(); x++ {
				p.SetColorIndex(x, y, uint8(pal.Index(f.img.RGBAAt(x, y))))
			}
		}
		g.Image = append(g.Image, p)
		g.Delay = append(g.Delay, f.delay)
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	return gif.EncodeAll(out, g)
}

// scale shrinks img to width by averaging the source pixels each output pixel covers.
func scale(img *image.RGBA, width int) *image.RGBA {
	sw, sh := img.Rect.Dx(), img.Rect.Dy()
	if width >= sw {
		return img
	}
	h := sh * width / sw
	out := image.NewRGBA(image.Rect(0, 0, width, h))
	for y := 0; y < h; y++ {
		y0, y1 := y*sh/h, max((y+1)*sh/h, y*sh/h+1)
		for x := 0; x < width; x++ {
			x0, x1 := x*sw/width, max((x+1)*sw/width, x*sw/width+1)
			var r, g, b, n int
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					c := img.RGBAAt(xx, yy)
					r, g, b, n = r+int(c.R), g+int(c.G), b+int(c.B), n+1
				}
			}
			out.SetRGBA(x, y, color.RGBA{uint8(r / n), uint8(g / n), uint8(b / n), 255})
		}
	}
	return out
}

// medianCut builds a palette of n colours from a sample of the frames' pixels.
func medianCut(imgs []*image.RGBA, n int) color.Palette {
	var px [][3]uint8
	for _, img := range imgs {
		for i := 0; i+3 < len(img.Pix); i += 4 * 7 { // every 7th pixel is plenty
			px = append(px, [3]uint8{img.Pix[i], img.Pix[i+1], img.Pix[i+2]})
		}
	}
	boxes := [][][3]uint8{px}
	for len(boxes) < n {
		bi, ch, best := -1, 0, -1
		for i, b := range boxes {
			if len(b) < 2 {
				continue
			}
			for c := 0; c < 3; c++ {
				lo, hi := 255, 0
				for _, p := range b {
					lo, hi = min(lo, int(p[c])), max(hi, int(p[c]))
				}
				if r := (hi - lo) * len(b); r > best {
					bi, ch, best = i, c, r
				}
			}
		}
		if bi < 0 || best == 0 {
			break
		}
		b := boxes[bi]
		sort.Slice(b, func(i, j int) bool { return b[i][ch] < b[j][ch] })
		mid := len(b) / 2
		boxes[bi] = b[:mid]
		boxes = append(boxes, b[mid:])
	}
	pal := make(color.Palette, 0, len(boxes))
	for _, b := range boxes {
		var r, g, bl int
		for _, p := range b {
			r, g, bl = r+int(p[0]), g+int(p[1]), bl+int(p[2])
		}
		k := max(len(b), 1)
		pal = append(pal, color.RGBA{uint8(r / k), uint8(g / k), uint8(bl / k), 255})
	}
	return pal
}
