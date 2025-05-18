package com.example.UserAuthenticationAndRoleManagement.User;

import com.example.UserAuthenticationAndRoleManagement.Guest.DTO.ReviewDTO;
import com.example.UserAuthenticationAndRoleManagement.Host.DTO.PropertyDTO;
import com.example.UserAuthenticationAndRoleManagement.Host.HostService;
import com.example.UserAuthenticationAndRoleManagement.User.DTO.CreateUserDTO;
import com.example.UserAuthenticationAndRoleManagement.User.DTO.NotificationDto;
import com.example.UserAuthenticationAndRoleManagement.auth.FirebasePrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Controller
@RequestMapping("/api/users")
public class UserController {
    private final UserService svc;
    private final HostService hostService;
    private final UserRepository userRepo;

    public UserController(UserService svc, UserRepository userRepo, HostService hostService) {
        this.svc = svc;
        this.hostService = hostService;
        this.userRepo = userRepo;
    }

    @GetMapping("/by-firebase-uid")
    @ResponseBody
    public Long getByFirebaseUid(@RequestParam String uid) {
        return userRepo
                .findByFirebaseUid(uid)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"
                ))
                .getUserId();
    }

    @GetMapping("/{id}/email")
    @ResponseBody
    public String getEmail(@PathVariable Long id) {
        return userRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,"User not found"))
                .getEmail();
    }

    @GetMapping
    public List<User> getAll() {
        return svc.fetchAll();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public User create(@RequestBody CreateUserDTO dto) {
        return svc.createUser(dto);
    }


    @GetMapping("/properties/all")
    public String getAllProperties(Model model) {
        List<PropertyDTO> properties  =hostService.getAllProperties();
        String roleName =  hostService.getRoleName();

        model.addAttribute("role", roleName);
        model.addAttribute("properties", properties);
        return "all-properties-list";

    }
    @GetMapping("/properties/{id}/details")
    public String getPropertyDetails(@PathVariable Integer id, Model model) {
        PropertyDTO property = hostService.getPropertyById(id);
        String roleName = hostService.getRoleName();
        String hostId = property.getHostId();
        User user= svc.fetchByFirebaseUid(hostId);
        List<ReviewDTO> reviews = hostService.getReviewsByPropertyId(id);

        model.addAttribute("reviews", reviews);
        model.addAttribute("firstname", user.getFirstName());
        model.addAttribute("lastname", user.getLastName());
        model.addAttribute("role", roleName);
        model.addAttribute("property", property);
        return "property-details";
    }
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id) {
        svc.deleteUser(id);
    }

    @GetMapping("/{id}/notifications")
    public List<NotificationDto> notifications(@PathVariable Long id) {
        return svc.getNotifications(id);
    }


    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof FirebasePrincipal firebasePrincipal) {
            String email = firebasePrincipal.getEmail();
            User user = svc.findByEmail(email);
            String roleName =user.getRole().name();
            model.addAttribute("role", roleName);
            return "home";
        }

        throw new IllegalStateException("Invalid principal type");
    }


}
