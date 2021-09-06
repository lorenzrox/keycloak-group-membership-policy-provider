package org.keycloak.representations.idm.authorization;

public class GroupMembershipPolicyRepresentation extends AbstractPolicyRepresentation {
    private String groupsClaim;
    private String pattern;
    private ResourceMatchTarget resourceMatchTarget;
    private GroupMatchTarget groupMatchTarget;
    private String resourceMatchAttributeName;
    private String groupMatchAttributeName;

    @Override
    public String getType() {
        return "group-membership";
    }

    public String getGroupsClaim() {
        return groupsClaim;
    }

    public void setGroupsClaim(String groupsClaim) {
        this.groupsClaim = groupsClaim;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public ResourceMatchTarget getResourceMatchTarget() {
        return resourceMatchTarget;
    }

    public void setResourceMatchTarget(ResourceMatchTarget target) {
        this.resourceMatchTarget = target;
    }

    public GroupMatchTarget getGroupMatchTarget() {
        return groupMatchTarget;
    }

    public void setGroupMatchTarget(GroupMatchTarget target) {
        this.groupMatchTarget = target;
    }

    public String getResourceMatchAttributeName() {
        return resourceMatchAttributeName;
    }

    public void setResourceMatchAttributeName(String name) {
        this.resourceMatchAttributeName = name;
    }

    public String getGroupMatchAttributeName() {
        return groupMatchAttributeName;
    }

    public void setGroupMatchAttributeName(String name) {
        this.groupMatchAttributeName = name;
    }
}
