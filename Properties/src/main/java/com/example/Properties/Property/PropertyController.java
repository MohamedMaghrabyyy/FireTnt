package com.example.Properties.Property;

import com.example.Properties.Annotations.RateLimit;
import com.example.Properties.Property.DTO.*;
import com.example.Properties.Property.Model.Property;
import com.example.Properties.Property.Model.Review;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
@Controller
@RequestMapping("/api/properties")
public class PropertyController {


    private final PropertyService propertyService;
    private  static final Logger LOGGER = LoggerFactory.getLogger(PropertyController.class);
    public PropertyController(PropertyService propertyService) {
        this.propertyService = propertyService;
    }

    @PostMapping("/create")
    @ResponseBody
    @RateLimit(limit = 80, duration = 60, keyPrefix = "createProperty")
    public ResponseEntity<String> createPropertyApi(@RequestBody @Valid CreatePropertyDTO dto) {
        propertyService.createProperty(dto);
        return ResponseEntity.ok("Property created successfully");
    }



    @GetMapping("/all")
    @ResponseBody
    @RateLimit(limit = 80, duration = 60, keyPrefix = "getAllProperties")
    public List<Property> getAllProperties() {
        List<Property> properties = propertyService.getAllProperties();
        return properties.stream()
                .map(p -> new Property(
                        p.getPropertyId(),
                        p.getTitle(),
                        p.getDescription(),
                        p.getPricePerNight(),
                        p.isBooked(),
                        p.getLocation(),
                        p.getPropertyType(),
                        p.getHostId()
                ))
                .toList();
    }

    @GetMapping("/host/{hostId}")
    @ResponseBody
    @RateLimit(limit = 80, duration = 60, keyPrefix = "getPropetiesByHostId")
    public List<Property> getPropertiesByHostId(@PathVariable String hostId) {
        List<Property> properties = propertyService.getPropertiesByHostId(hostId);
        return properties.stream()
                .map(p -> new Property(
                        p.getPropertyId(),
                        p.getTitle(),
                        p.getDescription(),
                        p.getPricePerNight(),
                        p.isBooked(),
                        p.getLocation(),
                        p.getPropertyType(),
                        p.getHostId()
                ))
                .toList();
    }



    @GetMapping("/{id}")
    @ResponseBody
    @RateLimit(limit = 80, duration = 60, keyPrefix = "getPropertyById")
    public ResponseEntity<Property> getPropertyById(@PathVariable Integer id) {
        Property property = propertyService.getPropertyById(id);
        if (property == null) {
            System.out.println("NULL PROPERTY");
        }
        return ResponseEntity.ok(property);
    }

    @PutMapping("/{id}/update")
    @RateLimit(limit = 80, duration = 60, keyPrefix = "updateProperty")
    public ResponseEntity<Property> updateProperty(@PathVariable Integer id, @RequestBody UpdatePropertyDTO dto) {
        Property updatedProperty = propertyService.updateProperty(id, dto);
        if (updatedProperty == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(updatedProperty);

}
    @DeleteMapping("/{id}")
    @RateLimit(limit = 80, duration = 60, keyPrefix = "deleteProperty")
    public ResponseEntity<Void> deleteProperty(@PathVariable Integer id) {
      propertyService.deleteProperty(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}/isBooked")
    @RateLimit(limit = 80, duration = 60, keyPrefix = "isBooked")
    public ResponseEntity<Boolean> isBooked(@PathVariable Integer id) {
        return ResponseEntity.ok(propertyService.isBooked(id));
    }

    //#############################################################


    // End points that call the Review Service
    @GetMapping("/reviews")
    @ResponseBody
    public ResponseEntity<List<Review>> getAllReviews() {
        List<Review> reviews = propertyService.getAllReviewsFromReviewService();
        return ResponseEntity.ok(reviews);
    }

    @GetMapping("/{id}/reviews")
    public ResponseEntity<List<Review>> getReviewsForProperty(@PathVariable("id") Integer propertyId) {
        List<Review> reviews = propertyService.getReviewsForProperty(propertyId);
        return ResponseEntity.ok(reviews);
    }

    @PostMapping("/{propertyId}/reviews")
    public ResponseEntity<Review> createReviewForProperty(
            @PathVariable Integer propertyId,
            @RequestBody CreateReviewWithPropertyIdDTO createReviewDTO) {

        Review createdReview = propertyService.createReviewForProperty(propertyId, createReviewDTO);
        return ResponseEntity.ok(createdReview);
    }

    // Update Review Text for Property by reviewId
    @PutMapping("/{propertyId}/reviews/{reviewId}/text")
    public ResponseEntity<Review> updateReviewTextForProperty(
            @PathVariable Integer propertyId,
            @PathVariable long reviewId,
            @RequestBody UpdateReviewTextDTO dto) {

        Review updatedReview = propertyService.updateReviewTextForProperty(propertyId, reviewId, dto);
        return ResponseEntity.ok(updatedReview);
    }

    // Update Review Rating for Property by reviewId
    @PutMapping("/{propertyId}/reviews/{reviewId}/rating")
    public ResponseEntity<Review> updateReviewRatingForProperty(
            @PathVariable Integer propertyId,
            @PathVariable long reviewId,
            @RequestBody UpdateReviewRatingDTO dto) {

        Review updatedReview = propertyService.updateReviewRatingForProperty(propertyId, reviewId, dto);
        return ResponseEntity.ok(updatedReview);
    }


}
