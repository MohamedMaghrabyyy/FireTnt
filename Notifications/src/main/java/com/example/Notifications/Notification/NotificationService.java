package com.example.Notifications.Notification;
import com.example.Notifications.Annotations.DistributedLock;
import com.example.Notifications.Notification.DTO.CreateNotificationDTO;
import jakarta.transaction.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class NotificationService {

    private final NotificationRepository notificationRepository;
    private final JavaMailSender mailSender;

    public NotificationService(NotificationRepository notificationRepository, JavaMailSender mailSender) {
        this.notificationRepository = notificationRepository;
        this.mailSender = mailSender;
    }



    public Notification getById(Long id) {
        return notificationRepository.findById(id)
                .orElseThrow(() ->
                        new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "Not found"));
    }

    public List<Notification> getByUser(Long userId) {
        return notificationRepository.findByRecipientId(userId);
    }

    @DistributedLock(
            keyPrefix = "notificationCreate",
            keyIdentifierExpression = "#dto.recipientId",
            leaseTime = 15,
            timeUnit = TimeUnit.SECONDS
    )
    @Transactional
    public Notification create(CreateNotificationDTO dto) {
        Notification n = new Notification();
        n.setRecipientId(dto.getRecipientId());
        n.setRecipientEmail(dto.getRecipientEmail()); // You may still store email for reference
        n.setMessage(dto.getMessage());  // The welcoming message for the user
        Notification saved = notificationRepository.save(n);

        // Here, you can log or return the notification to the client
        System.out.println("Notification created for User: " + dto.getRecipientEmail());
        System.out.println("Message: " + dto.getMessage());  // For debugging/logging

        return saved;  // Return the notification object
    }



    @DistributedLock(
            keyPrefix = "notificationRead",
            keyIdentifierExpression = "#id",
            leaseTime = 10,
            timeUnit = TimeUnit.SECONDS
    )
    @Transactional
    public Notification markAsRead(Long id) {
        Notification n = getById(id);
        n.markAsRead();
        return n;
    }


    @DistributedLock(
            keyPrefix = "notificationDelete",
            keyIdentifierExpression = "#id",
            leaseTime = 10,
            timeUnit = TimeUnit.SECONDS
    )
    @Transactional
    public void delete(Long id) {
        notificationRepository.deleteById(id);
    }
}
