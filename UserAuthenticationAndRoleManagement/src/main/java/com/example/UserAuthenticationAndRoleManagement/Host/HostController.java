package com.example.UserAuthenticationAndRoleManagement.Host;
import com.example.UserAuthenticationAndRoleManagement.Guest.DTO.BookingDTO;
import com.example.UserAuthenticationAndRoleManagement.Host.DTO.PropertyDTO;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.security.Principal;
import java.util.List;
import java.util.Objects;


@Controller
@RequestMapping("/host")
public class HostController {
    private final HostService hostService;
private  static final Logger LOGGER = LoggerFactory.getLogger(HostController.class);
    @Autowired
    public HostController(HostService hostService) {
        this.hostService = hostService;
       // this.userService = userService;

    }
    @GetMapping("/properties/create")
    public String showCreatePropertyForm(Model model) {
        String roleName = hostService.getRoleName();
        model.addAttribute("role", roleName);
        model.addAttribute("propertyForm", new PropertyDTO());
        return "add-property-form";
    }
    @GetMapping("/properties/edit/{id}")
    public String showUpdatePropertyForm(@PathVariable("id") Integer propertyId, Model model) {
        PropertyDTO property = hostService.getPropertyById(propertyId);
        String roleName = hostService.getRoleName();
        model.addAttribute("propertyId", propertyId);
        model.addAttribute("role", roleName);
        model.addAttribute("propertyForm", property);
        return "edit-property-form";
    }

    //#############################################################

    // End points that call the Property Service
    @PostMapping("/properties/create")
    public String createProperty(@Valid @ModelAttribute("propertyForm") PropertyDTO dto,
                                 BindingResult result,
                                 RedirectAttributes redirectAttributes,
                                 Principal principal) {

        String hostId = getHostIdFromPrincipal(principal);
        dto.setHostId(hostId);
        hostService.createProperty(dto);
        redirectAttributes.addFlashAttribute("success", "Property created successfully!");
        return "redirect:/host/properties";
    }
    private String getHostIdFromPrincipal(Principal principal) {
        // Extract user ID from FirebasePrincipal or session
        return hostService.getUidFromPrincipal(principal); // Example for testing
    }
    @PostMapping("/properties/edit/{id}")
    public String updateProperty(@PathVariable("id") Integer propertyId,
                                 @Valid @ModelAttribute("propertyForm") PropertyDTO dto,
                                 BindingResult result,
                                 RedirectAttributes redirectAttributes,
                                 Principal principal) {
        if (result.hasErrors()) {
            return "edit-property-form";
        }
        LOGGER.info("Updating property with booked status: {}", dto.getBooked());
        dto.setHostId(getHostIdFromPrincipal(principal)); // enforce correct host
        hostService.updateProperty(propertyId, dto);
        redirectAttributes.addFlashAttribute("success", "Property updated successfully!");
        return "redirect:/host/properties";
    }


    @GetMapping("/properties")
    public String viewHostProperties(Model model, Principal principal) {
        String hostId = getHostIdFromPrincipal(principal);
List<PropertyDTO> properties = hostService.getPropertiesForHost(hostId);
        String roleName =  hostService.getRoleName();
        model.addAttribute("role", roleName);
        model.addAttribute("properties", properties);
        return "host-properties";
    }

    @GetMapping("/properties/{id}/delete")
    public String deleteProperty(@PathVariable("id") Integer propertyId,
                                 RedirectAttributes redirectAttributes) {
        hostService.deleteProperty(propertyId);
        redirectAttributes.addFlashAttribute("success", "Property deleted successfully!");
        if (Objects.equals(hostService.getRoleName(), "HOST")) {
            return "redirect:/host/properties";
        }
        return "redirect:/api/users/properties/all";
    }

@GetMapping("/bookings")
public String viewBookings(Model model, Principal principal) {
    String hostId = getHostIdFromPrincipal(principal);
    List<BookingDTO> bookings = hostService.getAllBookingsForHost(hostId);
    String roleName = hostService.getRoleName();
    List<PropertyDTO> properties = hostService.getPropertiesForHost(hostId);

    model.addAttribute("properties", properties);
    model.addAttribute("role", roleName);
    model.addAttribute("bookings", bookings);
    return "host-bookings";
}
}