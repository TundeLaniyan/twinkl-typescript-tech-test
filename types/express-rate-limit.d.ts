declare module 'express-rate-limit' {
    import { RequestHandler, Request, Response, NextFunction } from 'express';

    interface RateLimitOptions {
        windowMs?: number; // Time window in milliseconds
        max?: number; // Maximum number of requests allowed in the time window
        message?: string | object; // Message sent when rate limit is exceeded
        statusCode?: number; // Status code to send on rate limit hit
        headers?: boolean; // Whether to send rate limit headers
        skipFailedRequests?: boolean; // Exclude failed requests from the rate count
        skipSuccessfulRequests?: boolean; // Exclude successful requests from the rate count
        keyGenerator?: (req: Request, res: Response) => string; // Function to generate a unique key for rate limiting
        handler?: (req: Request, res: Response, next: NextFunction) => any; // Function to handle rate limit hits
        onLimitReached?: (req: Request, res: Response, optionsUsed: RateLimitOptions) => void; // Callback on rate limit hit
    }

    export default function rateLimit(options?: RateLimitOptions): RequestHandler;
}
