package utils

import (
	"math/rand"
	"sort"
)

type Choice struct {
	Item   interface{}
	Weight uint
}

type Chooser struct {
	data   []Choice
	totals []int
	max    int
}

func NewChooser(cs ...Choice) Chooser {
	sort.Slice(cs, func(i, j int) bool {
		return cs[i].Weight < cs[j].Weight
	})
	totals := make([]int, len(cs))
	runningTotal := 0
	for i, c := range cs {
		runningTotal += int(c.Weight)
		totals[i] = runningTotal
	}
	return Chooser{data: cs, totals: totals, max: runningTotal}
}

func (chs Chooser) Pick() interface{} {
	r := rand.Intn(chs.max) + 1
	i := sort.SearchInts(chs.totals, r)
	return chs.data[i].Item
}
