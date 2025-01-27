package util

import (
	"sync/atomic"
)

type emptyLocker struct{}

func (emptyLocker) Lock()   {}
func (emptyLocker) Unlock() {}

var EmptyLocker emptyLocker

type IDataFrame[T any] interface {
	Reset()               // 重置数据,复用内存
	Ready()               // 标记为可读取
	ReaderEnter()         // 读取者数量+1
	ReaderTryEnter() bool // 尝试读取
	ReaderLeave()         // 读取者数量-1
	StartWrite() bool     // 开始写入
	SetSequence(uint32)   // 设置序号
	GetSequence() uint32  // 获取序号
	IsDiscarded() bool    // 是否已废弃
}

type RingWriter[T any, F IDataFrame[T]] struct {
	*Ring[F]    `json:"-" yaml:"-"`
	ReaderCount atomic.Int32 `json:"-" yaml:"-"`
	pool        *Ring[F]
	poolSize    int
	Size        int
	LastValue   F
	constructor func() F
	disposeFlag atomic.Int32
}

func (rb *RingWriter[T, F]) create(n int) (ring *Ring[F]) {
	ring = NewRing[F](n)
	for p, i := ring, n; i > 0; p, i = p.Next(), i-1 {
		p.Value = rb.constructor()
	}
	return
}

func (rb *RingWriter[T, F]) Init(n int, constructor func() F) *RingWriter[T, F] {
	rb.constructor = constructor
	rb.Ring = rb.create(n)
	rb.Size = n
	rb.LastValue = rb.Value
	rb.Value.StartWrite()
	return rb
}

func (rb *RingWriter[T, F]) Glow(size int) (newItem *Ring[F]) {
	if size < rb.poolSize {
		newItem = rb.pool.Unlink(size)
		rb.poolSize -= size
	} else if size == rb.poolSize {
		newItem = rb.pool
		rb.poolSize = 0
		rb.pool = nil
	} else {
		newItem = rb.create(size - rb.poolSize).Link(rb.pool)
		rb.poolSize = 0
		rb.pool = nil
	}
	rb.Link(newItem)
	rb.Size += size
	return
}

func (rb *RingWriter[T, F]) recycle(r *Ring[F]) {
	if rb.pool == nil {
		rb.pool = r
	} else {
		rb.pool.Link(r)
	}
}

func (rb *RingWriter[T, F]) Reduce(size int) {
	p := rb.Unlink(size)
	pSize := size
	rb.Size -= size
	// 遍历即将回收的节点，如果有读锁未释放，则丢弃，不回收该节点
	for i := 0; i < size; i++ {
		if !p.Value.IsDiscarded() && p.Value.StartWrite() { // 尝试加写锁，成功则说明该节点可正常回收
			p.Value.Reset()
			p.Value.Ready()
			rb.poolSize++
		} else {
			p.Value.Reset()
			if pSize == 1 {
				// last one，无法删除最后一个节点，直接返回即可（不回收）
				return
			}
			p = p.Prev()
			p.Unlink(1) // 丢弃该节点,不回收
			pSize--
		}
		p = p.Next()
	}
	rb.recycle(p)
}

func (rb *RingWriter[T, F]) Dispose() {
	if rb.disposeFlag.Add(-2) == -2 {
		rb.Value.Ready()
	}
}

func (rb *RingWriter[T, F]) Step() (normal bool) {
	if !rb.disposeFlag.CompareAndSwap(0, 1) {
		// already disposed
		return
	}
	rb.LastValue = rb.Value
	nextSeq := rb.LastValue.GetSequence() + 1
	next := rb.Next()
	if normal = next.Value.StartWrite(); normal {
		next.Value.Reset()
		rb.Ring = next
	} else {
		rb.Reduce(1)         //抛弃还有订阅者的节点
		rb.Ring = rb.Glow(1) //补充一个新节点
		if !rb.Value.StartWrite() {
			panic("can't start write")
		}
	}
	rb.Value.SetSequence(nextSeq)
	rb.LastValue.Ready()
	if !rb.disposeFlag.CompareAndSwap(1, 0) {
		rb.Value.Ready()
	}
	return
}

func (rb *RingWriter[T, F]) GetReaderCount() int32 {
	return rb.ReaderCount.Load()
}
