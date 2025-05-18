package com.example.Properties.Property.Model;
import jakarta.persistence.*;
@Entity
@Table(name = "properties")
public class Property {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long propertyId;

    private String title;
    private String description;
    private double pricePerNight;
    private boolean isBooked;

    private String location;
    private String propertyType;
    private String hostId;

public Property() {
}
    public Property(long propertyId, String title, String description, double pricePerNight, boolean isBooked, String location, String propertyType, String hostId) {
        this.propertyId = propertyId;
        this.title = title;
        this.description = description;
        this.pricePerNight = pricePerNight;
        this.isBooked = isBooked;
        this.location = location;
        this.propertyType = propertyType;
        this.hostId = hostId;

    }
    public long getPropertyId() {
        return propertyId;
    }

    public void setPropertyId(long propertyId) {
        this.propertyId = propertyId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public double getPricePerNight() {
        return pricePerNight;
    }

    public void setPricePerNight(double pricePerNight) {
        this.pricePerNight = pricePerNight;
    }

    public boolean isBooked() {
        return isBooked;
    }

    public void setBooked(boolean isBooked) {
        this.isBooked = isBooked;
    }

    public String getHostId() {
        return hostId;
    }

    public void setHostId(String hostId) {
        this.hostId = hostId;
    }
    public String getLocation() {
        return location;
    }
    public void setLocation(String location) {
        this.location = location;
    }
    public String getPropertyType() {
        return propertyType;
    }
    public void setPropertyType(String propertyType) {
        this.propertyType = propertyType;
    }
}