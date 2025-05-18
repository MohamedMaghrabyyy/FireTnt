package com.example.Properties.Property;

import com.example.Properties.Annotations.DistributedLock;
import com.example.Properties.PaymentAndBookingClient;
import com.example.Properties.Property.DTO.*;
import com.example.Properties.Property.Model.Property;
import com.example.Properties.Redis.RedisClient;
import com.example.Properties.Property.Model.Review;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.Properties.ReviewsClient;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class PropertyService {
    private PaymentAndBookingClient paymentAndBookingClient;
    private ReviewsClient reviewClient;
    private static final Logger log = LoggerFactory.getLogger(PropertyService.class); // Add logger
    private final PropertyRepository propertyRepository;
    @Autowired
    private RedisClient redisClient;
    @Autowired
    private ObjectMapper objectMapper; // Inject ObjectMapper
    private static final String ALL_PROPERTIES_CACHE_KEY = "properties:all";
    private static final Duration CACHE_TTL = Duration.ofMinutes(10);
    @Autowired
    public PropertyService(PropertyRepository propertyRepository, ReviewsClient reviewClient , PaymentAndBookingClient paymentAndBookingClient) {
        this.propertyRepository = propertyRepository;
        this.reviewClient = reviewClient;
        this.paymentAndBookingClient = paymentAndBookingClient;
    }

    @DistributedLock(
            keyPrefix = "property:create",
            keyIdentifierExpression = "#dto.hostId",
            leaseTime = 60,
            timeUnit = TimeUnit.SECONDS
    )
    public Property createProperty(CreatePropertyDTO dto) {
        Property property = new Property();
        property.setTitle(dto.getTitle());
        property.setDescription(dto.getDescription());
        property.setPricePerNight(dto.getPricePerNight());
        property.setHostId(dto.getHostId());
        property.setBooked(false);
        property.setPropertyType(dto.getPropertyType());
        property.setLocation(dto.getLocation());


        Property savedProperty = propertyRepository.save(property);

        // Invalidate caches
        try {
            String allPropertiesCacheKey = ALL_PROPERTIES_CACHE_KEY; // e.g., "property::all"
            redisClient.delete(allPropertiesCacheKey);
            log.info("[createProperty] Invalidated Redis cache key: {}", allPropertiesCacheKey);
        } catch (Exception e) {
            log.error("[createProperty] Failed to invalidate cache due to {}", e.getMessage());
        }

        return savedProperty;
    }

    public List<Property> getAllProperties() {

        try {
            String cached = redisClient.get(ALL_PROPERTIES_CACHE_KEY);
            if (cached != null) {
                log.info("Cache hit for key: {}", ALL_PROPERTIES_CACHE_KEY);
                // Deserialize the list
                return objectMapper.readValue(cached,
                        objectMapper.getTypeFactory().constructCollectionType(List.class, Property.class));
            }
        } catch (JsonProcessingException e) {
            log.error("Error deserializing property list from Redis for key {}: {}", ALL_PROPERTIES_CACHE_KEY, e.getMessage());
        } catch (Exception e) {
            log.error("[getAllProperties] Error accessing Redis for key {}: {}", ALL_PROPERTIES_CACHE_KEY, e.getMessage());
        }

        log.info("[getAllProperties] Cache miss for key: {}. Fetching from database.", ALL_PROPERTIES_CACHE_KEY);
        List<Property> properties = propertyRepository.findAll();

        if (!properties.isEmpty()) {
            try {
                String propertiesJson = objectMapper.writeValueAsString(properties);
                redisClient.set(ALL_PROPERTIES_CACHE_KEY, propertiesJson, CACHE_TTL);
                log.info("[getAllProperties] Stored {} properties in cache for key: {}", properties.size(), ALL_PROPERTIES_CACHE_KEY);
            } catch (JsonProcessingException e) {
                log.error("[getAllProperties] Error serializing property list for cache for key {}: {}", ALL_PROPERTIES_CACHE_KEY, e.getMessage());
            } catch (Exception e) {
                log.error("[getAllProperties] Error storing property list in Redis for key {}: {}", ALL_PROPERTIES_CACHE_KEY, e.getMessage());
            }
        }

        return properties;
    }


    public Property getPropertyById(Integer id) {
        // Check Redis cache first
        String key = "property::" + id;
        try {

        String cached = redisClient.get(key);
        if (cached != null) {
                log.info("[getPropertyById] Cache hit for key: {}", key);
                return objectMapper.readValue(cached, Property.class);
            }}
        catch (JsonProcessingException e) {
            log.error("[getPropertyById] Error deserializing cached rooms from Redis for key {}: {}", key, e.getMessage());
            // Proceed to fetch from DB if deserialization fails
        } catch (Exception e) {
            log.error("[getPropertyById] Error accessing Redis for key {}: {}", key, e.getMessage());
            // Proceed to fetch from DB if Redis access fails
        }
        // 2. If cache miss or error, fetch from database
        log.info("[getPropertyById] Cache miss for key: {}. Fetching from database.", key);
        Property property = propertyRepository.findById(id).orElse(null);
        // 3. Store the result in cache
        if (property != null) {
            try {
                String propertyJson = objectMapper.writeValueAsString(property);
                redisClient.set(key, propertyJson, CACHE_TTL); // Use set with TTL
                log.info("[getPropertyById] Stored property with id {} in cache for key: {}", id, key);
            } catch (JsonProcessingException e) {
                log.error("[getPropertyById] Error serializing property for caching for key {}: {}", key, e.getMessage());
            } catch (Exception e) {
                log.error("[getPropertyById] Error storing data in Redis for key {}: {}", key, e.getMessage());
            }
        }
        return property;
    }

    public List<Property> getPropertiesByHostId(String hostId) {
        return propertyRepository.findByHostId(hostId);
    }

    @DistributedLock(
            keyPrefix = "property:update",
            keyIdentifierExpression = "#id",
            leaseTime = 60,
            timeUnit = TimeUnit.SECONDS
    )
    public Property updateProperty(Integer id, UpdatePropertyDTO dto) {
        Property property = getPropertyById(id); // handles not found exception

        if (dto.getTitle() != null) property.setTitle(dto.getTitle());
        if (dto.getDescription() != null) property.setDescription(dto.getDescription());
        if (dto.getPricePerNight() != null) property.setPricePerNight(dto.getPricePerNight());
        property.setBooked(dto.getBooked());
        if (dto.getHostId() != null) property.setHostId(dto.getHostId());
        if (dto.getLocation() != null) property.setLocation(dto.getLocation());
        if (dto.getPropertyType() != null) property.setPropertyType(dto.getPropertyType());


        Property updated= propertyRepository.save(property);
        //Invalidate caches
        String propertyCacheKey = "property::" + id;
        try {
            redisClient.delete(propertyCacheKey); // Invalidate individual property cache
            redisClient.delete(ALL_PROPERTIES_CACHE_KEY); // Invalidate all properties list cache
            log.info("[updateProperty] Invalidated Redis cache keys: {}, {}", propertyCacheKey, ALL_PROPERTIES_CACHE_KEY);
        } catch (Exception e) {
            log.error("[updateProperty] Failed to invalidate cache keys: {}, {} due to {}", propertyCacheKey, ALL_PROPERTIES_CACHE_KEY, e.getMessage());
        }

        return updated;
    }

    @DistributedLock(
            keyPrefix = "property:delete",
            keyIdentifierExpression = "#id",
            leaseTime = 60,
            timeUnit = TimeUnit.SECONDS
    )
    public void deleteProperty(Integer id) {
        if (!propertyRepository.existsById(id)) {
            throw new RuntimeException("Property not found");
        }
        propertyRepository.deleteById(id);
        paymentAndBookingClient.deletBookingsByPropertyId(id);

        String propertyCacheKey = "property::" + id;
        try {
            redisClient.delete(propertyCacheKey); // Remove specific property cache
            redisClient.delete(ALL_PROPERTIES_CACHE_KEY); // Invalidate the list cache
            log.info("[deleteProperty] Invalidated cache keys: {}, {}", propertyCacheKey, ALL_PROPERTIES_CACHE_KEY);
        } catch (Exception e) {
            log.error("[deleteProperty] Error invalidating cache for keys {} and {}: {}", propertyCacheKey, ALL_PROPERTIES_CACHE_KEY, e.getMessage());
        }
    }

    public boolean isBooked(Integer id) {
        Property property = getPropertyById(id);
        return property.isBooked();
    }

    // ###################################################



    // Endpoints that call the Review service
    public List<Review> getAllReviewsFromReviewService() {
        return reviewClient.getAllReviews();
    }

    public List<Review> getReviewsForProperty(Integer propertyId) {
        return reviewClient.getReviewsByPropertyId(propertyId);
    }

    // Create review for property
    public Review createReviewForProperty(Integer propertyId, CreateReviewWithPropertyIdDTO createReviewDTO) {
        reviewClient.createReview(propertyId, createReviewDTO);
        return reviewClient.getReviewsByPropertyId(propertyId).get(0); // Assuming the latest review is the one created
    }

    // Update review text for property by reviewId
    public Review updateReviewTextForProperty(Integer propertyId, long reviewId, UpdateReviewTextDTO dto) {
        reviewClient.updateReviewTextForProperty(propertyId, reviewId, dto);
        return reviewClient.getReviewsByPropertyId(propertyId).stream()
                .filter(review -> review.getId() == reviewId)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Review not found"));
    }

    // Update review rating for property by reviewId
    public Review updateReviewRatingForProperty(Integer propertyId, long reviewId, UpdateReviewRatingDTO dto) {
        reviewClient.updateReviewRatingForProperty(propertyId, reviewId, dto);
        return reviewClient.getReviewsByPropertyId(propertyId).stream()
                .filter(review -> review.getId() == reviewId)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Review not found"));
    }


}
