package workers

import "sync"

type Pool[T any] struct {
	concurrency int
	jobs        chan T
	fn          func(T) error
	wg          sync.WaitGroup
	errs        []error
	mu          sync.Mutex
}

func New[T any](concurrency int, fn func(T) error) *Pool[T] {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Pool[T]{
		concurrency: concurrency,
		jobs:        make(chan T, concurrency*2),
		fn:          fn,
	}
}

func (p *Pool[T]) Start() {
	for range p.concurrency {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for job := range p.jobs {
				if err := p.fn(job); err != nil {
					p.mu.Lock()
					p.errs = append(p.errs, err)
					p.mu.Unlock()
				}
			}
		}()
	}
}

func (p *Pool[T]) Submit(job T) {
	p.jobs <- job
}

func (p *Pool[T]) Wait() []error {
	close(p.jobs)
	p.wg.Wait()
	return p.errs
}
