package com.agentshield.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Coarse defense-in-depth request size cap for the API surface, ahead of any business logic. */
@Component
public class RequestSizeLimitFilter extends OncePerRequestFilter {

    private final long maxRequestBytes;

    public RequestSizeLimitFilter(@Value("${agentshield.gateway.max-request-bytes:1048576}") long maxRequestBytes) {
        this.maxRequestBytes = maxRequestBytes;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long contentLength = request.getContentLengthLong();
        if (contentLength > maxRequestBytes) {
            response.setStatus(413);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"request body exceeds maximum allowed size\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
