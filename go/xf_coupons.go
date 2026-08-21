package benchmarks

// Coupon lookups used by checkout.

type Coupon struct{ Percent int }

type couponIndex struct{}

func (couponIndex) Lookup(code string) *Coupon { return nil }

var coupons couponIndex

func findCoupon(code string) *Coupon { c := coupons.Lookup(code); if c == nil { return &Coupon{Percent: 0} }; return c }
