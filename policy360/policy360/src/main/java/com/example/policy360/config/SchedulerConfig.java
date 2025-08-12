package com.example.policy360.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration
@ConditionalOnProperty(name = "policy360.scheduler.enabled", havingValue = "true", matchIfMissing = true)
@Slf4j
public class SchedulerConfig {

    @Value("${spring.task.scheduling.pool.size:10}")
    private int schedulingPoolSize;

    @Value("${spring.task.execution.pool.core-size:8}")
    private int executionCorePoolSize;

    @Value("${spring.task.execution.pool.max-size:16}")
    private int executionMaxPoolSize;

    @Value("${spring.task.execution.pool.queue-capacity:100}")
    private int executionQueueCapacity;

    // For scheduled tasks (@Scheduled annotations)
    @Bean(name = "policy360TaskScheduler", destroyMethod = "shutdown")
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(schedulingPoolSize); // Only method available
        scheduler.setThreadNamePrefix("Policy360-Scheduler-");
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        scheduler.setAwaitTerminationSeconds(30);
        scheduler.setRejectedExecutionHandler((runnable, executor) ->
                log.warn("Task rejected from scheduler thread pool: {}", runnable.toString()));
        scheduler.initialize();

        log.info("Policy360 Task Scheduler initialized with pool size: {}",
                scheduler.getPoolSize());
        return scheduler;
    }

    // For async task execution (@Async annotations)
    @Bean(name = "policy360AsyncTaskExecutor")
    public ThreadPoolTaskExecutor asyncTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(executionCorePoolSize);    // ✅ Available in ThreadPoolTaskExecutor
        executor.setMaxPoolSize(executionMaxPoolSize);      // ✅ Available in ThreadPoolTaskExecutor
        executor.setQueueCapacity(executionQueueCapacity);  // ✅ Available in ThreadPoolTaskExecutor
        executor.setThreadNamePrefix("Policy360-Async-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();

        log.info("Policy360 Async Task Executor initialized - Core: {}, Max: {}, Queue: {}",
                executionCorePoolSize, executionMaxPoolSize, executionQueueCapacity);
        return executor;
    }
}
