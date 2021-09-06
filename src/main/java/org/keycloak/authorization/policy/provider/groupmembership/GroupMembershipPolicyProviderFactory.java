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
import org.keycloak.representations.idm.authorization.GroupMatchTarget;
import org.keycloak.representations.idm.authorization.GroupMembershipPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceMatchTarget;

public class GroupMembershipPolicyProviderFactory
        implements PolicyProviderFactory<GroupMembershipPolicyRepresentation> {

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

        Map<String, String> config = policy.getConfig();
        representation.setGroupsClaim(config.get("groupsClaim"));
        representation.setPattern(config.get("groupPattern"));
        representation
                .setResourceMatchTarget(ResourceMatchTarget.valueOf(config.get("resourceMatchTarget").toUpperCase()));
        representation.setResourceMatchAttributeName(config.get("resourceMatchAttributeName"));
        representation.setGroupMatchTarget(GroupMatchTarget.valueOf(config.get("groupMatchTarget").toUpperCase()));
        representation.setGroupMatchAttributeName(config.get("groupMatchAttributeName"));

        return representation;
    }

    @Override
    public Class<GroupMembershipPolicyRepresentation> getRepresentationType() {
        return GroupMembershipPolicyRepresentation.class;
    }

    @Override
    public void onCreate(Policy policy, GroupMembershipPolicyRepresentation representation,
            AuthorizationProvider authorization) {
        updatePolicy(policy, representation.getGroupsClaim(), representation.getPattern(),
                representation.getResourceMatchTarget(), representation.getResourceMatchAttributeName(),
                representation.getGroupMatchTarget(), representation.getGroupMatchAttributeName(), authorization);
    }

    @Override
    public void onUpdate(Policy policy, GroupMembershipPolicyRepresentation representation,
            AuthorizationProvider authorization) {
        updatePolicy(policy, representation.getGroupsClaim(), representation.getPattern(),
                representation.getResourceMatchTarget(), representation.getResourceMatchAttributeName(),
                representation.getGroupMatchTarget(), representation.getGroupMatchAttributeName(), authorization);
    }

    @Override
    public void onImport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        Map<String, String> config = representation.getConfig();
        updatePolicy(policy, config.get("groupsClaim"), config.get("pattern"),
                ResourceMatchTarget.valueOf(config.get("resourceMatchTarget").toUpperCase()),
                config.get("resourceMatchAttributeName"),
                GroupMatchTarget.valueOf(config.get("groupMatchTarget").toUpperCase()),
                config.get("groupMatchAttributeName"), authorization);
    }

    @Override
    public void onExport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        Map<String, String> config = new HashMap<>();
        GroupMembershipPolicyRepresentation groupPolicy = toRepresentation(policy, authorization);

        String groupsClaim = groupPolicy.getGroupsClaim();
        if (groupsClaim != null) {
            config.put("groupsClaim", groupsClaim);
        }

        String pattern = groupPolicy.getPattern();
        if (pattern != null) {
            config.put("pattern", pattern);
        }

        config.put("resourceMatchTarget", groupPolicy.getResourceMatchTarget().name());

        if (groupPolicy.getResourceMatchTarget() == ResourceMatchTarget.ATTRIBUTE) {
            config.put("resourceMatchAttributeName", groupPolicy.getResourceMatchAttributeName());
        }

        config.put("groupMatchTarget", groupPolicy.getGroupMatchTarget().name());

        if (groupPolicy.getGroupMatchTarget() == GroupMatchTarget.ATTRIBUTE) {
            config.put("groupMatchAttributeName", groupPolicy.getGroupMatchAttributeName());
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

    private void updatePolicy(Policy policy, String groupsClaim, String pattern,
            ResourceMatchTarget resourceMatchTarget, String resourceMatchAttributeName,
            GroupMatchTarget groupMatchTarget, String groupMatchAttributeName, AuthorizationProvider authorization) {
        Map<String, String> config = new HashMap<>(policy.getConfig());

        if (groupsClaim != null) {
            config.put("groupsClaim", groupsClaim);
        }

        if (pattern != null) {
            config.put("pattern", pattern);
        }

        config.put("resourceMatchTarget", resourceMatchTarget.name());

        if (resourceMatchTarget == ResourceMatchTarget.ATTRIBUTE) {
            config.put("resourceMatchAttributeName", resourceMatchAttributeName);
        }

        config.put("groupMatchTarget", groupMatchTarget.name());

        if (groupMatchTarget == GroupMatchTarget.ATTRIBUTE) {
            config.put("groupMatchAttributeName", resourceMatchAttributeName);
        }

        policy.setConfig(config);
    }
}