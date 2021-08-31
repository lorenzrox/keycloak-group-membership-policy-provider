/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.representations.idm.authorization;

/**
 *
 * @author loren
 */
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
