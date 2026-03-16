package com.spantag.Apigatewayapplication;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

@Configuration
public class GatewayConfig {

    @Bean
    @Order(-1)
    public GlobalFilter loggingFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest req = exchange.getRequest();
            System.out.printf("[GATEWAY] %s %s%n",
                    req.getMethod(), req.getURI());
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                ServerHttpResponse res = exchange.getResponse();
                System.out.printf("[GATEWAY] Response: %s%n",
                        res.getStatusCode());
            }));
        };
    }
}
