/**
 * Recipe planner.
 *
 * Ingredient lines arrive as free text typed by the cook, so every parse here
 * has to answer for a line that does not match the shape it expects.
 */

export interface Ingredient {
  name: string
  quantity: number
  unit: string
}

export interface Recipe {
  id: string
  title: string
  servings: number
  ingredients: Ingredient[]
  notes?: string
}

const QUANTITY = /^(\d+(?:\.\d+)?)\s*([a-z]+)?\s+(.+)$/

// ts-null-quantity-match-bang-medium
export function parseQuantity(line: string): number {
  const matched = line.match(QUANTITY)
  if (!matched) {
    throw new Error(`ingredient line carries no quantity: ${line}`)
  }
  return Number(matched[1])
}

// ts-null-unit-split-destructure-medium
export function splitUnitEntry(entry: string): { amount: string; unit: string } {
  const parts = entry.split(':')
  if (parts.length < 2) {
    throw new Error(`pantry entry must be "amount:unit", got ${entry}`)
  }
  return { amount: parts[0].trim(), unit: parts[1].trim() }
}

// ts-null-notes-length-easy
export function hasCookNotes(recipe: Recipe): boolean {
  return (recipe.notes?.length ?? 0) > 0
}

export function scaleRecipe(recipe: Recipe, servings: number): Recipe {
  if (servings <= 0) {
    throw new Error('servings must be positive')
  }
  const factor = servings / recipe.servings
  return {
    ...recipe,
    servings,
    ingredients: recipe.ingredients.map((i) => ({ ...i, quantity: i.quantity * factor })),
  }
}
