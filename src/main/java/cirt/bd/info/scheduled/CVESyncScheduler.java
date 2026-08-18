package cirt.bd.info.scheduled;

import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import cirt.bd.info.service.CVESyncService;

@Component
public class CVESyncScheduler {
    private static final Logger log = LoggerFactory.getLogger(CVESyncScheduler.class);
    @Autowired
    private CVESyncService cveSyncService;
    private final AtomicBoolean running = new AtomicBoolean(false);
    // everyday at 2 AM
    @Scheduled(cron = "0 0 2 * * *", zone = "Asia/Dhaka")
    public void syncCves() {
        if(!running.compareAndSet(false, true)) return ;
        try {
            log.info("Started Running Daily Scheduled Job on syncCves");
            cveSyncService.synchronize();
        } catch(Exception e) {
            e.printStackTrace();
        } finally {
            running.set(false);
        }
    }
}
