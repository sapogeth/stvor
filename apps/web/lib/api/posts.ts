/**
 * Posts API Client
 * Handles all posts-related API calls to relay server
 */

import { getRelayBaseUrl } from '../config';

export interface Post {
  postId: string;
  authorId: string;
  authorUsername: string;
  content: string;
  imageUrl?: string;
  createdAt: number;
  likesCount: number;
  commentsCount: number;
  sharesCount: number;
}

export interface CreatePostRequest {
  content: string;
  imageUrl?: string;
}

export interface CreatePostResponse {
  success: boolean;
  postId?: string;
  error?: string;
}

export interface GetFeedResponse {
  posts: Post[];
}

export interface GetUserPostsResponse {
  posts: Post[];
}

/**
 * Create a new post
 */
export async function createPost(
  username: string,
  data: CreatePostRequest
): Promise<CreatePostResponse> {
  try {
    const response = await fetch(`${getRelayBaseUrl()}/posts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-username': username,
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      return { success: false, error: error.error || 'Failed to create post' };
    }

    return await response.json();
  } catch (error) {
    console.error('Error creating post:', error);
    return { success: false, error: 'Network error' };
  }
}

/**
 * Get posts feed (paginated)
 */
export async function getFeed(
  limit: number = 20,
  beforeTimestamp?: number
): Promise<Post[]> {
  try {
    const params = new URLSearchParams({ limit: limit.toString() });
    if (beforeTimestamp) {
      params.append('before', beforeTimestamp.toString());
    }

    const response = await fetch(`${getRelayBaseUrl()}/posts/feed?${params}`);

    if (!response.ok) {
      console.error('Failed to fetch feed');
      return [];
    }

    const data: GetFeedResponse = await response.json();
    return data.posts;
  } catch (error) {
    console.error('Error fetching feed:', error);
    return [];
  }
}

/**
 * Get posts by specific user
 */
export async function getUserPosts(
  username: string,
  limit: number = 20
): Promise<Post[]> {
  try {
    const response = await fetch(
      `${getRelayBaseUrl()}/posts/user/${encodeURIComponent(username)}?limit=${limit}`
    );

    if (!response.ok) {
      console.error('Failed to fetch user posts');
      return [];
    }

    const data: GetUserPostsResponse = await response.json();
    return data.posts;
  } catch (error) {
    console.error('Error fetching user posts:', error);
    return [];
  }
}

/**
 * Like a post
 */
export async function likePost(
  postId: string,
  username: string
): Promise<boolean> {
  try {
    const response = await fetch(`${getRelayBaseUrl()}/posts/${postId}/like`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-username': username,
      },
    });

    if (!response.ok) {
      console.error('Failed to like post');
      return false;
    }

    return true;
  } catch (error) {
    console.error('Error liking post:', error);
    return false;
  }
}

/**
 * Delete a post (author only)
 */
export async function deletePost(
  postId: string,
  username: string
): Promise<boolean> {
  try {
    const response = await fetch(`${getRelayBaseUrl()}/posts/${postId}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'x-username': username,
      },
    });

    if (!response.ok) {
      console.error('Failed to delete post');
      return false;
    }

    return true;
  } catch (error) {
    console.error('Error deleting post:', error);
    return false;
  }
}
