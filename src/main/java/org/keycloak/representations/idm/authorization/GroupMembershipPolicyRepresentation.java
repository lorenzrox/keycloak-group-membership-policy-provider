package org.keycloak.representations.idm.authorization;

public class GroupMembershipPolicyRepresentation extends AbstractPolicyRepresentation {
    private String groupsClaim;
    
    @Override
    public String getType() {
        return "groupmembership";
    }

    public String getGroupsClaim() {
        return groupsClaim;
    }

    public void setGroupsClaim(String groupsClaim) {
        this.groupsClaim = groupsClaim;
    }
}
