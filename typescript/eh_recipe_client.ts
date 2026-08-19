export interface Recipe {
  id: string
  title: string
  minutes: number
}

export interface RecipeLogger {
  error(message: string, cause: unknown): void
}

export class RecipeApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(message)
    this.name = 'RecipeApiError'
  }
}

export class RecipeParseError extends Error {
  constructor(
    message: string,
    readonly cause: unknown,
  ) {
    super(message)
    this.name = 'RecipeParseError'
  }
}

export class RecipeClient {
  constructor(
    private readonly baseUrl: string,
    private readonly logger: RecipeLogger,
  ) {}

  async loadRecipe(id: string): Promise<Recipe> {
    const response = await fetch(this.baseUrl + '/recipes/' + id)
    if (!response.ok) {
      const body = await response.text()
      throw new RecipeApiError('recipe ' + id + ' could not be loaded', response.status, body)
    }
    return (await response.json()) as Recipe
  }

  async searchRecipes(query: string): Promise<Recipe[]> {
    let response: Response
    try {
      response = await fetch(this.baseUrl + '/search?q=' + encodeURIComponent(query))
    } catch (error) {
      throw new RecipeApiError('recipe search is unreachable', 0, String(error))
    }
    const raw = await response.text()
    try {
      return JSON.parse(raw) as Recipe[]
    } catch (error) {
      throw new RecipeParseError('recipe search returned malformed JSON', error)
    }
  }

  async removeRecipe(id: string, onFailure: (message: string) => void): Promise<void> {
    try {
      await this.deleteRecipe(id)
    } catch (error) {
      this.logger.error('delete recipe ' + id + ' failed', error)
      onFailure('That recipe could not be deleted. Please try again.')
    }
  }

  private async deleteRecipe(id: string): Promise<void> {
    const response = await fetch(this.baseUrl + '/recipes/' + id, { method: 'DELETE' })
    if (!response.ok) {
      throw new RecipeApiError('recipe ' + id + ' was not deleted', response.status, await response.text())
    }
  }
}
