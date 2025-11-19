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
    public List<String> getIds() { return ids; }
    public List<String> getAuthors() { return authors; }
    public List<Integer> getKinds() { return kinds; }
    public List<String> getETags() { return eTags; }
    public List<String> getPTags() { return pTags; }
    public List<String> getTTags() { return tTags; }
    public List<String> getDTags() { return dTags; }
    public Long getSince() { return since; }
    public Long getUntil() { return until; }
    public Integer getLimit() { return limit; }

    // Setters
    public void setIds(List<String> ids) { this.ids = ids; }
    public void setAuthors(List<String> authors) { this.authors = authors; }
    public void setKinds(List<Integer> kinds) { this.kinds = kinds; }
    public void setETags(List<String> eTags) { this.eTags = eTags; }
    public void setPTags(List<String> pTags) { this.pTags = pTags; }
    public void setTTags(List<String> tTags) { this.tTags = tTags; }
    public void setDTags(List<String> dTags) { this.dTags = dTags; }
    public void setSince(Long since) { this.since = since; }
    public void setUntil(Long until) { this.until = until; }
    public void setLimit(Integer limit) { this.limit = limit; }

    /**
     * Create a builder for constructing filters.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for Filter construction.
     */
    public static class Builder {
        private final Filter filter = new Filter();

        public Builder ids(String... ids) {
            filter.ids = Arrays.asList(ids);
            return this;
        }

        public Builder ids(List<String> ids) {
            filter.ids = new ArrayList<>(ids);
            return this;
        }

        public Builder authors(String... authors) {
            filter.authors = Arrays.asList(authors);
            return this;
        }

        public Builder authors(List<String> authors) {
            filter.authors = new ArrayList<>(authors);
            return this;
        }

        public Builder kinds(int... kinds) {
            filter.kinds = new ArrayList<>();
            for (int kind : kinds) {
                filter.kinds.add(kind);
            }
            return this;
        }

        public Builder kinds(List<Integer> kinds) {
            filter.kinds = new ArrayList<>(kinds);
            return this;
        }

        public Builder eTags(String... eTags) {
            filter.eTags = Arrays.asList(eTags);
            return this;
        }

        public Builder eTags(List<String> eTags) {
            filter.eTags = new ArrayList<>(eTags);
            return this;
        }

        public Builder pTags(String... pTags) {
            filter.pTags = Arrays.asList(pTags);
            return this;
        }

        public Builder pTags(List<String> pTags) {
            filter.pTags = new ArrayList<>(pTags);
            return this;
        }

        public Builder tTags(String... tTags) {
            filter.tTags = Arrays.asList(tTags);
            return this;
        }

        public Builder tTags(List<String> tTags) {
            filter.tTags = new ArrayList<>(tTags);
            return this;
        }

        public Builder dTags(String... dTags) {
            filter.dTags = Arrays.asList(dTags);
            return this;
        }

        public Builder dTags(List<String> dTags) {
            filter.dTags = new ArrayList<>(dTags);
            return this;
        }

        public Builder since(long since) {
            filter.since = since;
            return this;
        }

        public Builder until(long until) {
            filter.until = until;
            return this;
        }

        public Builder limit(int limit) {
            filter.limit = limit;
            return this;
        }

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
