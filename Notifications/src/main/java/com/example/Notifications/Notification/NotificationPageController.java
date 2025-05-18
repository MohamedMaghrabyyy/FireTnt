package com.example.Notifications.Notification;
// HTML


import com.example.Notifications.Notification.DTO.CreateNotificationDTO;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
@RequestMapping("/api/notifications/guest")
public class NotificationPageController {

    private final NotificationService svc;
    private final UserAuthClient   userAuth;

    public NotificationPageController(
            NotificationService svc,
            UserAuthClient userAuth
    ) {
        this.svc      = svc;
        this.userAuth = userAuth;
    }

    @GetMapping("/my-notifications")
    public String listPage(
            @RequestParam("firebaseUid") String firebaseUid,
            Model model
    ) {
        //  convert → userId
        Long userId = userAuth.fetchUserIdByFirebaseUid(firebaseUid);
        String email = userAuth.fetchEmailByUserId(userId);

        //  Check if welcome message already exists
        boolean hasWelcome = svc.getByUser(userId).stream()
                .anyMatch(n -> n.getMessage().startsWith("Welcome to FireTnt"));

        if (!hasWelcome) {
            svc.create(new CreateNotificationDTO(
                    userId,
                    email,
                    "Welcome to FireTnt, "  + "!"
            ));
        }



        //  load list
        model.addAttribute("notifications", svc.getByUser(userId));
        model.addAttribute("role", "GUEST");

        return "myNotifications";
    }


}

