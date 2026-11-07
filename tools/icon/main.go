// Command icon redraws the CyberSoar EASM logos from the brand pack (docs/brand/logo-pack.png,
// the three logos on a dark background) and writes them where the program uses them:
//
//	rsrc_windows_amd64.syso  the app icon as the Windows icon resource linked into easm-agent.exe
//	                         (Explorer, the taskbar and the notification-area icon)
//	web/static/favicon.png   the app icon, as the browser-tab icon of the web interface
//	web/static/logo.png      the app icon, large (demo cards)
//	web/static/wordmark.png  the wing and "CyberSoar EASM", for the sidebar of the web interface
//	web/static/mark.png      the stacked "CS EASM" mark, for the sign-in and set-up pages
//
// The logos are redrawn at high resolution in their flat brand colours (render.go), with
// transparent backgrounds, so they are sharp and sit cleanly on the light and the dark theme
// alike. The app icon keeps its own black rounded tile. Large copies are also written to
// docs/brand. Run from the repository root after the pack changes:
//
//	go run ./tools/icon
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"sort"
)

const packFile = "docs/brand/logo-pack.png"

func main() {
	pack, err := loadPNG(packFile)
	if err != nil {
		fail(err)
	}
	bg := background(pack)

	// The three logos sit between the pack's dashed dividers (rough areas; each is trimmed to its
	// content). Each is redrawn at 6 times the pack's resolution, then scaled down to each size.
	const scale = 6
	iconArea := image.Rect(50, 140, 345, 430)
	icon := square(trim(render(pack, iconArea, bg, scale, findTile(pack, iconArea, bg)), 0.05), 0.02)
	mark := trim(render(pack, image.Rect(415, 200, 600, 370), bg, scale, nil), 0.05)
	word := trim(render(pack, image.Rect(632, 220, 990, 350), bg, scale, nil), 0.05)
	height := func(img *image.NRGBA, h int) *image.NRGBA {
		b := img.Bounds()
		return resize(img, int(math.Round(float64(b.Dx())*float64(h)/float64(b.Dy()))), h)
	}

	sizes := []int{16, 20, 24, 32, 40, 48, 64, 256}
	var frames [][]byte
	for _, s := range sizes {
		frames = append(frames, mustPNG(resize(icon, s, s)))
	}
	write("rsrc_windows_amd64.syso", iconObject(sizes, frames))
	write("web/static/favicon.png", mustPNG(resize(icon, 64, 64)))
	write("web/static/logo.png", mustPNG(resize(icon, 256, 256)))
	// The web interface shows the wordmark 44 and the mark 94 pixels high: three and two times
	// that keeps them sharp on high-DPI screens.
	write("web/static/wordmark.png", mustPNG(height(word, 132)))
	write("web/static/mark.png", mustPNG(height(mark, 188)))
	write("docs/brand/app-icon.png", mustPNG(resize(icon, 1024, 1024)))
	write("docs/brand/wordmark.png", mustPNG(height(word, 320)))
	write("docs/brand/mark.png", mustPNG(height(mark, 400)))
	fmt.Printf("background %v; redrawn icon %dpx, mark %v, wordmark %v\n", bg, icon.Bounds().Dx(), mark.Bounds().Size(), word.Bounds().Size())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "icon:", err)
	os.Exit(1)
}

func write(name string, b []byte) {
	if err := os.WriteFile(name, b, 0o644); err != nil { //nolint:gosec // G306: a source file of the repository
		fail(err)
	}
	fmt.Println("wrote", name)
}

func loadPNG(name string) (image.Image, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return png.Decode(f)
}

func mustPNG(img image.Image) []byte {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		fail(err)
	}
	return buf.Bytes()
}

type rgb struct{ r, g, b float64 } // 0..255

func at(img image.Image, x, y int) rgb {
	r, g, b, _ := img.At(x, y).RGBA()
	return rgb{float64(r >> 8), float64(g >> 8), float64(b >> 8)}
}

// background is the pack's background colour: the median of its top and bottom rows.
func background(img image.Image) rgb {
	bnd := img.Bounds()
	var rs, gs, bs []float64
	for x := bnd.Min.X; x < bnd.Max.X; x++ {
		for _, y := range []int{bnd.Min.Y + 4, bnd.Max.Y - 5} {
			c := at(img, x, y)
			rs, gs, bs = append(rs, c.r), append(gs, c.g), append(bs, c.b)
		}
	}
	return rgb{median(rs), median(gs), median(bs)}
}

func median(v []float64) float64 {
	sort.Float64s(v)
	return v[len(v)/2]
}

func dist(a, b rgb) float64 {
	return math.Sqrt((a.r-b.r)*(a.r-b.r) + (a.g-b.g)*(a.g-b.g) + (a.b-b.b)*(a.b-b.b))
}

func clamp8(f float64) uint8 { return uint8(math.Round(math.Max(0, math.Min(255, f)))) }

// roundedBox is the signed distance from (x, y) to a box of half-size hw×hh with corner radius r (negative inside).
func roundedBox(x, y, hw, hh, r float64) float64 {
	qx, qy := math.Abs(x)-(hw-r), math.Abs(y)-(hh-r)
	out := math.Hypot(math.Max(qx, 0), math.Max(qy, 0))
	return out + math.Min(math.Max(qx, qy), 0) - r
}

// trim cuts an image to the pixels that are at least minAlpha opaque, plus a 2-pixel margin.
func trim(img *image.NRGBA, minAlpha float64) *image.NRGBA {
	b := img.Bounds()
	box := image.Rectangle{Min: b.Max, Max: b.Min}
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if float64(img.NRGBAAt(x, y).A)/255 >= minAlpha {
				box = box.Union(image.Rect(x, y, x+1, y+1))
			}
		}
	}
	box = image.Rect(box.Min.X-2, box.Min.Y-2, box.Max.X+2, box.Max.Y+2).Intersect(b)
	out := image.NewNRGBA(image.Rect(0, 0, box.Dx(), box.Dy()))
	for y := box.Min.Y; y < box.Max.Y; y++ {
		for x := box.Min.X; x < box.Max.X; x++ {
			out.SetNRGBA(x-box.Min.X, y-box.Min.Y, img.NRGBAAt(x, y))
		}
	}
	return out
}

// square centres an image on a transparent square canvas with a small margin (a fraction of the side).
func square(img *image.NRGBA, margin float64) *image.NRGBA {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	side := int(math.Ceil(float64(max(w, h)) * (1 + 2*margin)))
	out := image.NewNRGBA(image.Rect(0, 0, side, side))
	ox, oy := (side-w)/2, (side-h)/2
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			out.SetNRGBA(x+ox, y+oy, img.NRGBAAt(x, y))
		}
	}
	return out
}

// resize scales with area averaging when shrinking and bilinear filtering when enlarging,
// in premultiplied alpha so transparent pixels do not darken the edges.
func resize(src *image.NRGBA, w, h int) *image.NRGBA {
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	out := image.NewNRGBA(image.Rect(0, 0, w, h))
	sx, sy := float64(sw)/float64(w), float64(sh)/float64(h)
	px := func(x, y int) (r, g, b, a float64) {
		x, y = max(0, min(sw-1, x)), max(0, min(sh-1, y))
		c := src.NRGBAAt(x, y)
		a = float64(c.A) / 255
		return float64(c.R) * a, float64(c.G) * a, float64(c.B) * a, a
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var r, g, b, a, n float64
			if sx >= 1 && sy >= 1 { // shrinking: average the source area
				for yy := int(float64(y) * sy); yy < int(math.Ceil(float64(y+1)*sy)); yy++ {
					for xx := int(float64(x) * sx); xx < int(math.Ceil(float64(x+1)*sx)); xx++ {
						pr, pg, pb, pa := px(xx, yy)
						r, g, b, a, n = r+pr, g+pg, b+pb, a+pa, n+1
					}
				}
			} else { // enlarging: bilinear
				fx, fy := (float64(x)+0.5)*sx-0.5, (float64(y)+0.5)*sy-0.5
				x0, y0 := int(math.Floor(fx)), int(math.Floor(fy))
				tx, ty := fx-float64(x0), fy-float64(y0)
				for _, s := range [][3]float64{{0, 0, (1 - tx) * (1 - ty)}, {1, 0, tx * (1 - ty)}, {0, 1, (1 - tx) * ty}, {1, 1, tx * ty}} {
					pr, pg, pb, pa := px(x0+int(s[0]), y0+int(s[1]))
					r, g, b, a, n = r+pr*s[2], g+pg*s[2], b+pb*s[2], a+pa*s[2], n+s[2]
				}
			}
			if a <= 0 {
				continue
			}
			out.SetNRGBA(x, y, color.NRGBA{clamp8(r / a), clamp8(g / a), clamp8(b / a), clamp8(a / n * 255)})
		}
	}
	return out
}

// iconObject builds a COFF object file holding one icon group (resource ID 1) made
// of the given PNG frames, in the layout the Go linker merges into a program's
// .rsrc section. PNG frames are understood by Windows Vista and later.
func iconObject(sizes []int, frames [][]byte) []byte {
	n := len(frames)
	le := binary.LittleEndian
	dir := func(b []byte, ids []uint32, offs []uint32, sub bool) []byte {
		hdr := make([]byte, 16)
		le.PutUint16(hdr[14:], uint16(len(ids))) // all entries are numeric IDs
		b = append(b, hdr...)
		for i, id := range ids {
			e := make([]byte, 8)
			le.PutUint32(e, id)
			o := offs[i]
			if sub {
				o |= 0x80000000
			}
			le.PutUint32(e[4:], o)
			b = append(b, e...)
		}
		return b
	}
	// Offsets of each part, in the order they are laid out.
	const dirSize = 16
	rootOff := uint32(0)
	iconTypeOff := rootOff + dirSize + 2*8
	groupTypeOff := iconTypeOff + dirSize + uint32(n)*8
	langOff := groupTypeOff + dirSize + 8 // n icon language dirs, then the group's
	dataEntryOff := langOff + uint32(n+1)*(dirSize+8)
	blobOff := dataEntryOff + uint32(n+1)*16

	group := make([]byte, 6+14*n)
	le.PutUint16(group[2:], 1) // type: icon
	le.PutUint16(group[4:], uint16(n))
	for i, s := range sizes {
		e := group[6+14*i:]
		if s < 256 {
			e[0], e[1] = byte(s), byte(s)
		}
		le.PutUint16(e[4:], 1)  // planes
		le.PutUint16(e[6:], 32) // bits per pixel
		le.PutUint32(e[8:], uint32(len(frames[i])))
		le.PutUint16(e[12:], uint16(i+1)) // the RT_ICON resource ID
	}
	blobs := append(append([][]byte{}, frames...), group)
	blobAt := make([]uint32, len(blobs))
	at := blobOff
	for i, b := range blobs {
		blobAt[i] = at
		at += uint32((len(b) + 7) &^ 7)
	}

	var sec []byte
	sec = dir(sec, []uint32{3, 14}, []uint32{iconTypeOff, groupTypeOff}, true) // RT_ICON, RT_GROUP_ICON
	ids, offs := make([]uint32, n), make([]uint32, n)
	for i := range ids {
		ids[i], offs[i] = uint32(i+1), langOff+uint32(i)*(dirSize+8)
	}
	sec = dir(sec, ids, offs, true)
	sec = dir(sec, []uint32{1}, []uint32{langOff + uint32(n)*(dirSize+8)}, true)
	for i := 0; i <= n; i++ {
		sec = dir(sec, []uint32{0x0409}, []uint32{dataEntryOff + uint32(i)*16}, false) // en-US
	}
	var relocs []uint32 // offsets of the OffsetToData fields, which hold section-relative addresses
	for i, b := range blobs {
		e := make([]byte, 16)
		le.PutUint32(e, blobAt[i])
		le.PutUint32(e[4:], uint32(len(b)))
		relocs = append(relocs, uint32(len(sec)))
		sec = append(sec, e...)
	}
	for _, b := range blobs {
		sec = append(sec, b...)
		for len(sec)%8 != 0 {
			sec = append(sec, 0)
		}
	}

	const fileHdr, secHdr = 20, 40
	rawAt := uint32(fileHdr + secHdr)
	relAt := rawAt + uint32(len(sec))
	symAt := relAt + uint32(len(relocs))*10
	var out []byte
	h := make([]byte, fileHdr)
	le.PutUint16(h[0:], 0x8664) // AMD64
	le.PutUint16(h[2:], 1)      // one section
	le.PutUint32(h[8:], symAt)
	le.PutUint32(h[12:], 1) // one symbol
	out = append(out, h...)
	s := make([]byte, secHdr)
	copy(s, ".rsrc")
	le.PutUint32(s[16:], uint32(len(sec)))
	le.PutUint32(s[20:], rawAt)
	le.PutUint32(s[24:], relAt)
	le.PutUint16(s[32:], uint16(len(relocs)))
	le.PutUint32(s[36:], 0x40000040) // initialised data, readable
	out = append(out, s...)
	out = append(out, sec...)
	for _, r := range relocs {
		e := make([]byte, 10)
		le.PutUint32(e, r)
		le.PutUint32(e[4:], 0) // symbol 0: the section itself
		le.PutUint16(e[8:], 3) // IMAGE_REL_AMD64_ADDR32NB
		out = append(out, e...)
	}
	sym := make([]byte, 18)
	copy(sym, ".rsrc")
	le.PutUint16(sym[12:], 1) // section number
	sym[16] = 3               // storage class: static
	out = append(out, sym...)
	out = append(out, 4, 0, 0, 0) // empty string table
	return out
}
