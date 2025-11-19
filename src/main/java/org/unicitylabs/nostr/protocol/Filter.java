package org.unicitylabs.nostr.protocol;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Nostr subscription filter as defined in NIP-01.
 * Filters specify which events should be sent to a subscription.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Filter {

    /** Event IDs to match */
    @JsonProperty("ids")
    private List<String> ids;

    /** Author public keys to match */
    @JsonProperty("authors")
    private List<String> authors;

    /** Event kinds to match */
    @JsonProperty("kinds")
    private List<Integer> kinds;

    /** Events referencing these event IDs (e tag) */
    @JsonProperty("#e")
    private List<String> eTags;

    /** Events referencing these pubkeys (p tag) */
    @JsonProperty("#p")
    private List<String> pTags;

    /** Events with these t tags (topics/hashtags) */
    @JsonProperty("#t")
    private List<String> tTags;

    /** Events with these d tags (identifier for parameterized replaceable) */
    @JsonProperty("#d")
    private List<String> dTags;

    /** Minimum creation timestamp (inclusive) */
    @JsonProperty("since")
    private Long since;

    /** Maximum creation timestamp (inclusive) */
    @JsonProperty("until")
    private Long until;

    /** Maximum number of events to return */
    @JsonProperty("limit")
    private Integer limit;

    /**
     * Default constructor for Jackson.
     */
    public Filter() {}

    // Getters
    /**
     * Gets the event IDs to filter.
     * @return list of event IDs to filter
     */
    public List<String> getIds() { return ids; }

    /**
     * Gets the author public keys to filter.
     * @return list of author public keys to filter
     */
    public List<String> getAuthors() { return authors; }

    /**
     * Gets the event kinds to filter.
     * @return list of event kinds to filter
     */
    public List<Integer> getKinds() { return kinds; }

    /**
     * Gets the "e" tags to filter.
     * @return list of "e" tags to filter
     */
    public List<String> getETags() { return eTags; }

    /**
     * Gets the "p" tags to filter.
     * @return list of "p" tags to filter
     */
    public List<String> getPTags() { return pTags; }

    /**
     * Gets the "t" tags to filter.
     * @return list of "t" tags to filter
     */
    public List<String> getTTags() { return tTags; }

    /**
     * Gets the "d" tags to filter.
     * @return list of "d" tags to filter
     */
    public List<String> getDTags() { return dTags; }

    /**
     * Gets the timestamp for filtering events since.
     * @return timestamp for filtering events since
     */
    public Long getSince() { return since; }

    /**
     * Gets the timestamp for filtering events until.
     * @return timestamp for filtering events until
     */
    public Long getUntil() { return until; }

    /**
     * Gets the maximum number of events to return.
     * @return maximum number of events to return
     */
    public Integer getLimit() { return limit; }

    // Setters
    /**
     * Sets the event IDs to filter.
     * @param ids list of event IDs to filter
     */
    public void setIds(List<String> ids) { this.ids = ids; }

    /**
     * Sets the author public keys to filter.
     * @param authors list of author public keys to filter
     */
    public void setAuthors(List<String> authors) { this.authors = authors; }

    /**
     * Sets the event kinds to filter.
     * @param kinds list of event kinds to filter
     */
    public void setKinds(List<Integer> kinds) { this.kinds = kinds; }

    /**
     * Sets the "e" tags to filter.
     * @param eTags list of "e" tags to filter
     */
    public void setETags(List<String> eTags) { this.eTags = eTags; }

    /**
     * Sets the "p" tags to filter.
     * @param pTags list of "p" tags to filter
     */
    public void setPTags(List<String> pTags) { this.pTags = pTags; }

    /**
     * Sets the "t" tags to filter.
     * @param tTags list of "t" tags to filter
     */
    public void setTTags(List<String> tTags) { this.tTags = tTags; }

    /**
     * Sets the "d" tags to filter.
     * @param dTags list of "d" tags to filter
     */
    public void setDTags(List<String> dTags) { this.dTags = dTags; }

    /**
     * Sets the timestamp for filtering events since.
     * @param since timestamp for filtering events since
     */
    public void setSince(Long since) { this.since = since; }

    /**
     * Sets the timestamp for filtering events until.
     * @param until timestamp for filtering events until
     */
    public void setUntil(Long until) { this.until = until; }

    /**
     * Sets the maximum number of events to return.
     * @param limit maximum number of events to return
     */
    public void setLimit(Integer limit) { this.limit = limit; }

    /**
     * Create a builder for constructing filters.
     *
     * @return a new Filter builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for Filter construction.
     */
    public static class Builder {
        private final Filter filter = new Filter();

        /**
         * Creates a new Builder.
         */
        public Builder() {
        }

        /**
         * Sets event IDs to filter.
         * @param ids event IDs to filter
         * @return this builder
         */
        public Builder ids(String... ids) {
            filter.ids = Arrays.asList(ids);
            return this;
        }

        /**
         * Sets event IDs to filter.
         * @param ids event IDs to filter
         * @return this builder
         */
        public Builder ids(List<String> ids) {
            filter.ids = new ArrayList<>(ids);
            return this;
        }

        /**
         * Sets author public keys to filter.
         * @param authors author public keys to filter
         * @return this builder
         */
        public Builder authors(String... authors) {
            filter.authors = Arrays.asList(authors);
            return this;
        }

        /**
         * Sets author public keys to filter.
         * @param authors author public keys to filter
         * @return this builder
         */
        public Builder authors(List<String> authors) {
            filter.authors = new ArrayList<>(authors);
            return this;
        }

        /**
         * Sets event kinds to filter.
         * @param kinds event kinds to filter
         * @return this builder
         */
        public Builder kinds(int... kinds) {
            filter.kinds = new ArrayList<>();
            for (int kind : kinds) {
                filter.kinds.add(kind);
            }
            return this;
        }

        /**
         * Sets event kinds to filter.
         * @param kinds event kinds to filter
         * @return this builder
         */
        public Builder kinds(List<Integer> kinds) {
            filter.kinds = new ArrayList<>(kinds);
            return this;
        }

        /**
         * Sets "e" tags to filter.
         * @param eTags "e" tags to filter
         * @return this builder
         */
        public Builder eTags(String... eTags) {
            filter.eTags = Arrays.asList(eTags);
            return this;
        }

        /**
         * Sets "e" tags to filter.
         * @param eTags "e" tags to filter
         * @return this builder
         */
        public Builder eTags(List<String> eTags) {
            filter.eTags = new ArrayList<>(eTags);
            return this;
        }

        /**
         * Sets "p" tags to filter.
         * @param pTags "p" tags to filter
         * @return this builder
         */
        public Builder pTags(String... pTags) {
            filter.pTags = Arrays.asList(pTags);
            return this;
        }

        /**
         * Sets "p" tags to filter.
         * @param pTags "p" tags to filter
         * @return this builder
         */
        public Builder pTags(List<String> pTags) {
            filter.pTags = new ArrayList<>(pTags);
            return this;
        }

        /**
         * Sets "t" tags to filter.
         * @param tTags "t" tags to filter
         * @return this builder
         */
        public Builder tTags(String... tTags) {
            filter.tTags = Arrays.asList(tTags);
            return this;
        }

        /**
         * Sets "t" tags to filter.
         * @param tTags "t" tags to filter
         * @return this builder
         */
        public Builder tTags(List<String> tTags) {
            filter.tTags = new ArrayList<>(tTags);
            return this;
        }

        /**
         * Sets "d" tags to filter.
         * @param dTags "d" tags to filter
         * @return this builder
         */
        public Builder dTags(String... dTags) {
            filter.dTags = Arrays.asList(dTags);
            return this;
        }

        /**
         * Sets "d" tags to filter.
         * @param dTags "d" tags to filter
         * @return this builder
         */
        public Builder dTags(List<String> dTags) {
            filter.dTags = new ArrayList<>(dTags);
            return this;
        }

        /**
         * Sets timestamp for filtering events since.
         * @param since timestamp for filtering events since
         * @return this builder
         */
        public Builder since(long since) {
            filter.since = since;
            return this;
        }

        /**
         * Sets timestamp for filtering events until.
         * @param until timestamp for filtering events until
         * @return this builder
         */
        public Builder until(long until) {
            filter.until = until;
            return this;
        }

        /**
         * Sets maximum number of events to return.
         * @param limit maximum number of events to return
         * @return this builder
         */
        public Builder limit(int limit) {
            filter.limit = limit;
            return this;
        }

        /**
         * Builds the Filter.
         * @return the constructed Filter
         */
        public Filter build() {
            return filter;
        }
    }

    @Override
    public String toString() {
        return "Filter{" +
                "ids=" + (ids != null ? ids.size() : 0) +
                ", authors=" + (authors != null ? authors.size() : 0) +
                ", kinds=" + kinds +
                ", since=" + since +
                ", until=" + until +
                ", limit=" + limit +
                '}';
    }
}
