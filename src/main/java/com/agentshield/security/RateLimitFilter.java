package com.agentshield.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Simple fixed-window rate limiter for the agent-facing gateway API, keyed by bearer token
 * (falling back to remote address). Deliberately dependency-free (no Bucket4j/Redis) to keep
 * the MVP free of extra paid/infra requirements — swap for a distributed limiter behind a
 * load balancer with multiple instances.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final int maxRequestsPerWindow;
    private final long windowMillis;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimitFilter(
            @Value("${agentshield.gateway.rate-limit.max-requests-per-minute:60}") int maxRequestsPerWindow) {
        this.maxRequestsPerWindow = maxRequestsPerWindow;
        this.windowMillis = 60_000L;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/gateway/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String key = rateLimitKey(request);
        Window window = windows.computeIfAbsent(key, k -> new Window(System.currentTimeMillis()));

        synchronized (window) {
            long now = System.currentTimeMillis();
            if (now - window.windowStart > windowMillis) {
                window.windowStart = now;
                window.count.set(0);
            }
            if (window.count.incrementAndGet() > maxRequestsPerWindow) {
                response.setStatus(429);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"rate limit exceeded, try again later\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private String rateLimitKey(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        return auth != null && !auth.isBlank() ? auth : request.getRemoteAddr();
    }

    private static final class Window {
        volatile long windowStart;
        final AtomicInteger count = new AtomicInteger(0);

        Window(long windowStart) {
            this.windowStart = windowStart;
        }
    }
}
