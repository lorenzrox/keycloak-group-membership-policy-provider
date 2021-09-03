package org.keycloak.authorization.policy.provider.groupmembership;

import java.util.HashMap;
import java.util.Map;
import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.representations.idm.authorization.GroupMembershipPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;

public class GroupMembershipPolicyProviderFactory implements PolicyProviderFactory<GroupMembershipPolicyRepresentation> {

    private GroupMembershipPolicyProvider provider = new GroupMembershipPolicyProvider(this::toRepresentation);

    @Override
    public String getId() {
        return "group-membership";
    }

    @Override
    public String getName() {
        return "Group Membership";
    }

    @Override
    public String getGroup() {
        return "Identity Based";
    }

    @Override
    public PolicyProvider create(AuthorizationProvider authorization) {
        return provider;
    }

    @Override
    public PolicyProvider create(KeycloakSession session) {
        return provider;
    }

    @Override
    public GroupMembershipPolicyRepresentation toRepresentation(Policy policy, AuthorizationProvider authorization) {
        GroupMembershipPolicyRepresentation representation = new GroupMembershipPolicyRepresentation();

        representation.setGroupsClaim(policy.getConfig().get("groupsClaim"));

        return representation;
    }

    @Override
    public Class<GroupMembershipPolicyRepresentation> getRepresentationType() {
        return GroupMembershipPolicyRepresentation.class;
    }

    @Override
    public void onCreate(Policy policy, GroupMembershipPolicyRepresentation representation, AuthorizationProvider authorization) {
        updatePolicy(policy, representation.getGroupsClaim(), authorization);
    }

    @Override
    public void onUpdate(Policy policy, GroupMembershipPolicyRepresentation representation, AuthorizationProvider authorization) {
        updatePolicy(policy, representation.getGroupsClaim(), authorization);
    }

    @Override
    public void onImport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        updatePolicy(policy, representation.getConfig().get("groupsClaim"),  authorization);
    }

    @Override
    public void onExport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        Map<String, String> config = new HashMap<>();
        GroupMembershipPolicyRepresentation groupPolicy = toRepresentation(policy, authorization);
        
        String groupsClaim = groupPolicy.getGroupsClaim();

        if (groupsClaim != null) {
            config.put("groupsClaim", groupsClaim);
        }

        representation.setConfig(config);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(event -> {
        });
    }

    @Override
    public void close() {

    }
    
    private void updatePolicy(Policy policy, String groupsClaim, AuthorizationProvider authorization) {
        Map<String, String> config = new HashMap<>(policy.getConfig());

        if (groupsClaim != null) {
            config.put("groupsClaim", groupsClaim);
        }

        policy.setConfig(config);
    }
}