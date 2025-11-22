interface RateLimitRecord {
  count: number;
  resetTime: number;
  firstSeen: number;
}

interface RateLimitStore {
  [key: string]: RateLimitRecord;
}

class RateLimiter {
  private store: RateLimitStore = {};
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    // Start cleanup process every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);
  }

  check(identifier: string, limit = 100, windowMs = 60000): {
    success: boolean;
    remaining: number;
    resetTime: number;
    retryAfter: number;
  } {
    const now = Date.now();
    const record = this.store[identifier];

    // If no record exists or window has expired, create new record
    if (!record || now > record.resetTime) {
      this.store[identifier] = {
        count: 1,
        resetTime: now + windowMs,
        firstSeen: now
      };
      
      return {
        success: true,
        remaining: limit - 1,
        resetTime: now + windowMs,
        retryAfter: 0
      };
    }

    // Increment counter if under limit
    if (record.count < limit) {
      record.count++;
      
      return {
        success: true,
        remaining: limit - record.count,
        resetTime: record.resetTime,
        retryAfter: 0
      };
    }

    // Rate limit exceeded
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);
    
    return {
      success: false,
      remaining: 0,
      resetTime: record.resetTime,
      retryAfter
    };
  }

  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, record] of Object.entries(this.store)) {
      if (now > record.resetTime + 60000) { // Keep records 1 minute after expiry
        delete this.store[key];
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`[RateLimiter] Cleaned up ${cleaned} expired records`);
    }
  }
}

// Create singleton instance
const rateLimiter = new RateLimiter();

// Export improved functions
export function rateLimitPerIdentifier(
  identifier: string,
  limit = 100,
  windowMs = 60000
): {
  success: boolean;
  remaining: number;
  resetTime: number;
  retryAfter: number;
} {
  return rateLimiter.check(identifier, limit, windowMs);
}

// Backward compatibility
export function rateLimit(
  key: string,
  limit = 100,
  windowMs = 60000,
): { success: boolean; remaining: number; resetTime: number } {
  const result = rateLimiter.check(key, limit, windowMs);
  return {
    success: result.success,
    remaining: result.remaining,
    resetTime: result.resetTime
  };
}

export function createRateLimitMiddleware(limit = 100, windowMs = 60000) {
  return (clientId: string) => rateLimit(clientId, limit, windowMs)
}
