/**
 * API layer demonstrating cross-file data flow patterns.
 */

import { UserService } from './service';
import { validateUserId, sanitizeSearchQuery } from './validators';

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface User {
  id: number;
  name: string;
  email: string;
}

/**
 * UserApi handles HTTP requests for user operations.
 */
export class UserApi {
  constructor(private userService: UserService) {}

  /**
   * Get user by ID from request parameter.
   *
   * SAFE VERSION: ID is validated before service call.
   * Matches template: ts-multifile-sqli-safe
   */
  async getUser(requestId: string): Promise<ApiResponse<User>> {
    // Validation in API layer
    if (!validateUserId(requestId)) {
      return { success: false, error: 'invalid id' };
    }

    try {
      // Safe: validated ID passed to service
      const user = await this.userService.findById(requestId);
      if (!user) {
        return { success: false, error: 'not found' };
      }
      return { success: true, data: user };
    } catch (error) {
      return { success: false, error: 'internal error' };
    }
  }

  /**
   * Search users by query string.
   *
   * SAFE VERSION: Query is sanitized and service uses parameterized query.
   * Matches template: ts-multifile-sqli-search-safe
   */
  async searchUsers(query: string): Promise<ApiResponse<User[]>> {
    // Sanitization in API layer
    const safeQuery = sanitizeSearchQuery(query);

    try {
      // Service uses parameterized query
      const users = await this.userService.search(safeQuery);
      return { success: true, data: users };
    } catch (error) {
      return { success: false, error: 'search failed' };
    }
  }

  /**
   * Create a new user.
   *
   * SAFE VERSION: Input is validated, service uses parameterized query.
   */
  async createUser(name: string, email: string): Promise<ApiResponse<User>> {
    if (!name || !email) {
      return { success: false, error: 'name and email required' };
    }

    try {
      const user = await this.userService.create(name, email);
      return { success: true, data: user };
    } catch (error) {
      return { success: false, error: 'creation failed' };
    }
  }
}

/**
 * ContentApi handles content display requests.
 */
export class ContentApi {
  /**
   * Render user-provided content safely.
   *
   * SAFE VERSION: Content is sanitized before rendering.
   * Matches template: ts-multifile-xss-safe
   */
  renderContent(userContent: string): string {
    // Sanitize HTML to prevent XSS
    const sanitized = this.sanitizeHtml(userContent);
    return `<div class="content">${sanitized}</div>`;
  }

  private sanitizeHtml(html: string): string {
    // Escape HTML entities
    return html
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }
}
