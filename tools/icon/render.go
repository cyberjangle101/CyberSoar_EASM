package main

import (
	"image"
	"image/color"
	"math"
)

// The pack is a small, lossy image, so simply enlarging it gives soft, blotchy logos. Instead
// each logo is redrawn at a higher resolution from what the pack shows: every pixel is sorted
// into the background or one of the brand colours, those maps are smoothed to remove the
// compression noise, and each output pixel takes the colour whose map is strongest there. Edges
// come out sharp at any size, and colours keep the shading the pack has within each colour.

// inks are the brand colours in the pack (measured from it).
var inks = []rgb{
	{194, 90, 20}, // orange
	{124, 24, 44}, // crimson
	{46, 155, 84}, // green
}

// tileColour is the app icon's black tile.
var tileColour = rgb{9, 9, 9}

// tile is a rounded rectangle in pack coordinates.
type tile struct{ cx, cy, hw, hh, rad float64 }

func (t *tile) inside(x, y float64) bool {
	return t != nil && roundedBox(x-t.cx, y-t.cy, t.hw, t.hh, t.rad) <= 0
}

// classMaps holds, for one area of the pack, how strongly each pixel belongs to the
// background (class 0) and to each ink (1..n), and the colour sums of each ink class.
type classMaps struct {
	w, h int
	mem  [][]float64 // [class][pixel]
	col  [][]rgb     // [ink class][pixel], membership-weighted colour
}

func buildMaps(img image.Image, r image.Rectangle, bgs []rgb) *classMaps {
	w, h := r.Dx(), r.Dy()
	n := len(inks) + 1
	m := &classMaps{w: w, h: h, mem: make([][]float64, n), col: make([][]rgb, n)}
	for c := range m.mem {
		m.mem[c] = make([]float64, w*h)
		m.col[c] = make([]rgb, w*h)
	}
	const sigma = 30.0 // how far (in RGB) a colour can stray from its ink, given the compression noise
	weight := func(d float64) float64 { return math.Exp(-d * d / (2 * sigma * sigma)) }
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			p := at(img, r.Min.X+x, r.Min.Y+y)
			i := y*w + x
			db := math.Inf(1)
			for _, b := range bgs {
				db = math.Min(db, dist(p, b))
			}
			ws := []float64{weight(db)}
			for _, k := range inks {
				ws = append(ws, weight(dist(p, k)))
			}
			sum := 0.0
			for _, v := range ws {
				sum += v
			}
			if sum < 1e-12 { // far from everything: give it to the nearest class
				best := 0
				ds := []float64{db}
				for _, k := range inks {
					ds = append(ds, dist(p, k))
				}
				for c := range ds {
					if ds[c] < ds[best] {
						best = c
					}
				}
				ws = make([]float64, n)
				ws[best], sum = 1, 1
			}
			for c := range ws {
				v := ws[c] / sum
				m.mem[c][i] = v
				m.col[c][i] = rgb{p.r * v, p.g * v, p.b * v}
			}
		}
	}
	for c := range m.mem {
		m.mem[c] = blurF(m.mem[c], w, h)
		m.col[c] = blurC(m.col[c], w, h)
	}
	return m
}

// gauss is a small Gaussian kernel (sigma 0.9 pixels) that removes the pack's block noise
// without closing the gaps between the wing's feathers.
var gauss = func() []float64 {
	k := make([]float64, 5)
	s := 0.0
	for i := range k {
		x := float64(i - 2)
		k[i] = math.Exp(-x * x / (2 * 0.9 * 0.9))
		s += k[i]
	}
	for i := range k {
		k[i] /= s
	}
	return k
}()

func blurF(v []float64, w, h int) []float64 {
	tmp, out := make([]float64, len(v)), make([]float64, len(v))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			s := 0.0
			for i, k := range gauss {
				s += k * v[y*w+max(0, min(w-1, x+i-2))]
			}
			tmp[y*w+x] = s
		}
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			s := 0.0
			for i, k := range gauss {
				s += k * tmp[max(0, min(h-1, y+i-2))*w+x]
			}
			out[y*w+x] = s
		}
	}
	return out
}

func blurC(v []rgb, w, h int) []rgb {
	r, g, b := make([]float64, len(v)), make([]float64, len(v)), make([]float64, len(v))
	for i, c := range v {
		r[i], g[i], b[i] = c.r, c.g, c.b
	}
	r, g, b = blurF(r, w, h), blurF(g, w, h), blurF(b, w, h)
	out := make([]rgb, len(v))
	for i := range out {
		out[i] = rgb{r[i], g[i], b[i]}
	}
	return out
}

// cubicWeights are the Catmull-Rom weights of the four samples around fraction t. Cubic
// interpolation keeps the redrawn edges smooth curves rather than the faint facets of linear.
func cubicWeights(t float64) [4]float64 {
	t2, t3 := t*t, t*t*t
	return [4]float64{
		(-t3 + 2*t2 - t) / 2,
		(3*t3 - 5*t2 + 2) / 2,
		(-3*t3 + 4*t2 + t) / 2,
		(t3 - t2) / 2,
	}
}

// bilinear samples a map at pack-relative position (x, y), in pixel-centre coordinates
// (bicubic, despite the name kept for its callers).
func bilinear(v []float64, w, h int, x, y float64) float64 {
	x0, y0 := int(math.Floor(x)), int(math.Floor(y))
	wx, wy := cubicWeights(x-float64(x0)), cubicWeights(y-float64(y0))
	s := 0.0
	for j := 0; j < 4; j++ {
		yy := max(0, min(h-1, y0+j-1))
		for i := 0; i < 4; i++ {
			s += wx[i] * wy[j] * v[yy*w+max(0, min(w-1, x0+i-1))]
		}
	}
	return s
}

func bilinearC(v []rgb, w, h int, x, y float64) rgb {
	x0, y0 := int(math.Floor(x)), int(math.Floor(y))
	wx, wy := cubicWeights(x-float64(x0)), cubicWeights(y-float64(y0))
	var s rgb
	for j := 0; j < 4; j++ {
		yy := max(0, min(h-1, y0+j-1))
		for i := 0; i < 4; i++ {
			c, k := v[yy*w+max(0, min(w-1, x0+i-1))], wx[i]*wy[j]
			s.r, s.g, s.b = s.r+k*c.r, s.g+k*c.g, s.b+k*c.b
		}
	}
	return s
}

// render redraws area r of the pack at scale times its size. Pixels that belong to the
// background are transparent, except inside the app icon's tile (t), which is drawn as a clean
// rounded rectangle. Each output pixel averages 4×4 samples, for smooth edges.
func render(img image.Image, r image.Rectangle, bg rgb, scale float64, t *tile) *image.NRGBA {
	bgs := []rgb{bg}
	if t != nil {
		bgs = append(bgs, tileColour)
	}
	m := buildMaps(img, r, bgs)
	W, H := int(math.Round(float64(r.Dx())*scale)), int(math.Round(float64(r.Dy())*scale))
	out := image.NewNRGBA(image.Rect(0, 0, W, H))
	const k = 4
	for oy := 0; oy < H; oy++ {
		for ox := 0; ox < W; ox++ {
			var sr, sg, sb, sa float64
			for sy := 0; sy < k; sy++ {
				for sx := 0; sx < k; sx++ {
					// position in the area, in pixel-centre coordinates
					x := (float64(ox)+(float64(sx)+0.5)/k)/scale - 0.5
					y := (float64(oy)+(float64(sy)+0.5)/k)/scale - 0.5
					best, bv := 0, -1.0
					for c := range m.mem {
						if v := bilinear(m.mem[c], m.w, m.h, x, y); v > bv {
							best, bv = c, v
						}
					}
					var c rgb
					switch {
					case best > 0:
						sum := bilinearC(m.col[best], m.w, m.h, x, y)
						c = rgb{sum.r / bv, sum.g / bv, sum.b / bv}
					case t.inside(float64(r.Min.X)+x+0.5, float64(r.Min.Y)+y+0.5):
						c = tileColour
					default:
						continue
					}
					sr, sg, sb, sa = sr+c.r, sg+c.g, sb+c.b, sa+1
				}
			}
			if sa == 0 {
				continue
			}
			out.SetNRGBA(ox, oy, color.NRGBA{clamp8(sr / sa), clamp8(sg / sa), clamp8(sb / sa), clamp8(sa / (k * k) * 255)})
		}
	}
	return out
}

// findTile locates the app icon's black tile in area r: the rows and columns where most
// pixels are much darker than the background.
func findTile(img image.Image, r image.Rectangle, bg rgb) *tile {
	lum := func(c rgb) float64 { return 0.2126*c.r + 0.7152*c.g + 0.0722*c.b }
	dark := lum(bg) * 0.6
	rows, cols := map[int]int{}, map[int]int{}
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if lum(at(img, x, y)) < dark {
				rows[y]++
				cols[x]++
			}
		}
	}
	edge := func(m map[int]int, lo, hi int) (int, int) {
		best := 0
		for _, n := range m {
			best = max(best, n)
		}
		a, b := hi, lo
		for i := lo; i < hi; i++ {
			if m[i] > best/2 {
				a, b = min(a, i), max(b, i)
			}
		}
		return a, b
	}
	x0, x1 := edge(cols, r.Min.X, r.Max.X)
	y0, y1 := edge(rows, r.Min.Y, r.Max.Y)
	hw, hh := float64(x1-x0+1)/2, float64(y1-y0+1)/2
	return &tile{cx: float64(x0) + hw, cy: float64(y0) + hh, hw: hw, hh: hh, rad: 0.38 * math.Min(hw, hh)}
}
