package rsaencryption;

import com.google.gson.annotations.SerializedName;

public class PayLoadRequest {

    @SerializedName("first_field")
    private final String firstField;
    @SerializedName("second_field")
    private final String secondField;

    public PayLoadRequest(String firstField, String secondField) {
        this.firstField = firstField;
        this.secondField = secondField;
    }
}
