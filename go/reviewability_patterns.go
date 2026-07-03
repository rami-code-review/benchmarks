//go:build reviewability

// Package benchmarks contains exact template patterns for benchmark testing.
// Each function contains the EXACT OriginalCode from templates.go.
//
// Reviewability fixtures carry a dedicated build tag: their stub types (Order,
// User) reuse names already defined in patterns.go, so they must not compile
// under the shared "patterns" tag.
package benchmarks

import "errors"

type reviewOrderStatus string

const StatusPaid reviewOrderStatus = "paid"

type Order struct {
	ID     string
	Status reviewOrderStatus
}

type User struct {
	approver bool
}

func (u User) CanApproveOrders() bool { return u.approver }

var ErrForbidden = errors.New("forbidden")

func markApproved(id string) error    { return nil }
func enqueueShipment(id string) error { return nil }

func canApproveOrder(order Order, user User) bool {
	return order.Status == StatusPaid && user.CanApproveOrders()
}

type Invoice struct {
	CustomerTier  string
	SubtotalCents int
	DiscountCents int
}

type DiscountPolicy struct{}

func (DiscountPolicy) DiscountFor(tier string, subtotalCents int) int { return 0 }

// go-reviewability-duplicated-policy-hard - exact multi-line
func canFinalizeOrder(order Order, user User) bool {
	return order.Status == StatusPaid && user.CanApproveOrders()
}

func approveOrder(order Order, user User) error {
	if !canFinalizeOrder(order, user) {
		return ErrForbidden
	}
	return markApproved(order.ID)
}

func shipOrder(order Order, user User) error {
	if !canFinalizeOrder(order, user) {
		return ErrForbidden
	}
	return enqueueShipment(order.ID)
}

// go-reviewability-ownership-boundary-hard - exact multi-line
func ApplyInvoiceDiscount(invoice *Invoice, policy DiscountPolicy) {
	invoice.DiscountCents = policy.DiscountFor(invoice.CustomerTier, invoice.SubtotalCents)
}

// go-fp-reviewability-central-policy - exact multi-line
func approveOrderWithSharedPolicy(order Order, user User) error {
	if !canApproveOrder(order, user) {
		return ErrForbidden
	}
	return markApproved(order.ID)
}
