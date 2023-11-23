package org.keycloak.authorization.policy.provider.groupmembership;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.authorization.GroupMatchTarget;
import org.keycloak.representations.idm.authorization.GroupMembershipPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceMatchTarget;

public class GroupMembershipPolicyProviderFactory
        implements PolicyProviderFactory<GroupMembershipPolicyRepresentation>, ConfiguredProvider {
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    private static final String GROUPS_CLAIM = "groupsClaim";
    private static final String GROUPS_CLAIM_LABEL = "authz-policy-group-membership.claim.label";
    private static final String GROUPS_CLAIM_HELP_TEXT = "authz-policy-group-membership.claim.tooltip";

    private static final String PATTERN = "pattern";
    private static final String PATTERN_LABEL = "authz-policy-group-membership.pattern.label";
    private static final String PATTERN_HELP_TEXT = "authz-policy-group-membership.pattern.tooltip";

    private static final String RESOURCE_MATCH_TARGET = "resourceMatchTarget";
    private static final String RESOURCE_MATCH_TARGET_LABEL = "authz-policy-group-membership.resource-match-target.label";
    private static final String RESOURCE_MATCH_TARGET_HELP_TEXT = "authz-policy-group-membership.resource-match-target.tooltip";

    private static final String RESOURCE_MATCH_ATTRIBUTE_NAME = "resourceMatchAttributeName";
    private static final String RESOURCE_MATCH_ATTRIBUTE_NAME_LABEL = "authz-policy-group-membership.resource-match-attribute-name.label";
    private static final String RESOURCE_MATCH_ATTRIBUTE_NAME_HELP_TEXT = "authz-policy-group-membership.resource-match-attribute-name.tooltip";

    private static final String GROUP_MATCH_TARGET = "groupMatchTarget";
    private static final String GROUP_MATCH_TARGET_LABEL = "authz-policy-group-membership.group-match-target.label";
    private static final String GROUP_MATCH_TARGET_HELP_TEXT = "authz-policy-group-membership.group-match-target.tooltip";

    private static final String GROUP_MATCH_ATTRIBUTE_NAME = "groupMatchAttributeName";
    private static final String GROUP_MATCH_ATTRIBUTE_NAME_LABEL = "authz-policy-group-membership.group-match-attribute-name.label";
    private static final String GROUP_MATCH_ATTRIBUTE_NAME_HELP_TEXT = "authz-policy-group-membership.group-match-attribute-name.tooltip";

    private static final String PROVIDER_ID = "group-membership";

    private GroupMembershipPolicyProvider provider = new GroupMembershipPolicyProvider(this::toRepresentation);

    static {
        ProviderConfigProperty groupsClaimProperty = new ProviderConfigProperty();
        groupsClaimProperty.setName(GROUPS_CLAIM);
        groupsClaimProperty.setLabel(GROUPS_CLAIM_LABEL);
        groupsClaimProperty.setType(ProviderConfigProperty.STRING_TYPE);
        groupsClaimProperty.setHelpText(GROUPS_CLAIM_HELP_TEXT);
        configProperties.add(groupsClaimProperty);

        ProviderConfigProperty patternProperty = new ProviderConfigProperty();
        patternProperty.setName(PATTERN);
        patternProperty.setLabel(PATTERN_LABEL);
        patternProperty.setType(ProviderConfigProperty.STRING_TYPE);
        patternProperty.setHelpText(PATTERN_HELP_TEXT);

        configProperties.add(patternProperty);

        ProviderConfigProperty resourceMatchTargetProperty = new ProviderConfigProperty();
        resourceMatchTargetProperty.setName(RESOURCE_MATCH_TARGET);
        resourceMatchTargetProperty.setLabel(RESOURCE_MATCH_TARGET_LABEL);
        resourceMatchTargetProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        resourceMatchTargetProperty.setHelpText(RESOURCE_MATCH_TARGET_HELP_TEXT);
        resourceMatchTargetProperty.setOptions(Stream.of(ResourceMatchTarget.values())
                .map(Enum::name).collect(Collectors.toList()));

        configProperties.add(resourceMatchTargetProperty);

        ProviderConfigProperty resourceMatchAttributeProperty = new ProviderConfigProperty();
        resourceMatchAttributeProperty.setName(RESOURCE_MATCH_ATTRIBUTE_NAME);
        resourceMatchAttributeProperty.setLabel(RESOURCE_MATCH_ATTRIBUTE_NAME_LABEL);
        resourceMatchAttributeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        resourceMatchAttributeProperty.setHelpText(RESOURCE_MATCH_ATTRIBUTE_NAME_HELP_TEXT);

        configProperties.add(resourceMatchAttributeProperty);

        ProviderConfigProperty groupMatchTargetProperty = new ProviderConfigProperty();
        groupMatchTargetProperty.setName(GROUP_MATCH_TARGET);
        groupMatchTargetProperty.setLabel(GROUP_MATCH_TARGET_LABEL);
        groupMatchTargetProperty.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        groupMatchTargetProperty.setHelpText(GROUP_MATCH_TARGET_HELP_TEXT);
        groupMatchTargetProperty.setOptions(Stream.of(GroupMatchTarget.values())
                .map(Enum::name).collect(Collectors.toList()));

        configProperties.add(groupMatchTargetProperty);

        ProviderConfigProperty groupMatchAttributeProperty = new ProviderConfigProperty();
        groupMatchAttributeProperty.setName(GROUP_MATCH_ATTRIBUTE_NAME);
        groupMatchAttributeProperty.setLabel(GROUP_MATCH_ATTRIBUTE_NAME_LABEL);
        groupMatchAttributeProperty.setType(ProviderConfigProperty.STRING_TYPE);
        groupMatchAttributeProperty.setHelpText(GROUP_MATCH_ATTRIBUTE_NAME_HELP_TEXT);

        configProperties.add(groupMatchAttributeProperty);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
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
    public String getHelpText() {
        return "Define conditions for your permissions where a set of one or more roles is permitted to access an object.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
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
        representation.setGroupsClaim(config.get(GROUPS_CLAIM));
        representation.setPattern(config.get(PATTERN));
        representation
                .setResourceMatchTarget(ResourceMatchTarget.valueOf(config.get(RESOURCE_MATCH_TARGET).toUpperCase()));
        representation.setResourceMatchAttributeName(config.get(RESOURCE_MATCH_ATTRIBUTE_NAME));
        representation.setGroupMatchTarget(GroupMatchTarget.valueOf(config.get(GROUP_MATCH_TARGET).toUpperCase()));
        representation.setGroupMatchAttributeName(config.get(GROUP_MATCH_ATTRIBUTE_NAME));

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
        updatePolicy(policy, config.get(GROUPS_CLAIM), config.get(PATTERN),
                ResourceMatchTarget.valueOf(config.get(RESOURCE_MATCH_TARGET).toUpperCase()),
                config.get(RESOURCE_MATCH_ATTRIBUTE_NAME),
                GroupMatchTarget.valueOf(config.get(GROUP_MATCH_TARGET).toUpperCase()),
                config.get(GROUP_MATCH_ATTRIBUTE_NAME), authorization);
    }

    @Override
    public void onExport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        Map<String, String> config = new HashMap<>();
        GroupMembershipPolicyRepresentation groupPolicy = toRepresentation(policy, authorization);

        String groupsClaim = groupPolicy.getGroupsClaim();
        if (groupsClaim != null) {
            config.put(GROUPS_CLAIM, groupsClaim);
        }

        String pattern = groupPolicy.getPattern();
        if (pattern != null) {
            config.put(PATTERN, pattern);
        }

        config.put(RESOURCE_MATCH_TARGET, groupPolicy.getResourceMatchTarget().name());

        if (groupPolicy.getResourceMatchTarget() == ResourceMatchTarget.ATTRIBUTE) {
            config.put(RESOURCE_MATCH_ATTRIBUTE_NAME, groupPolicy.getResourceMatchAttributeName());
        }

        config.put(GROUP_MATCH_TARGET, groupPolicy.getGroupMatchTarget().name());

        if (groupPolicy.getGroupMatchTarget() == GroupMatchTarget.ATTRIBUTE) {
            config.put(GROUP_MATCH_ATTRIBUTE_NAME, groupPolicy.getGroupMatchAttributeName());
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
            config.put(GROUPS_CLAIM, groupsClaim);
        }

        if (pattern == null) {
            config.remove(PATTERN);
        } else {
            config.put(PATTERN, pattern);
        }

        config.put(RESOURCE_MATCH_TARGET, resourceMatchTarget.name());

        if (resourceMatchTarget == ResourceMatchTarget.ATTRIBUTE) {
            config.put(RESOURCE_MATCH_ATTRIBUTE_NAME, resourceMatchAttributeName);
        } else {
            config.remove(RESOURCE_MATCH_ATTRIBUTE_NAME);
        }

        config.put(GROUP_MATCH_TARGET, groupMatchTarget.name());

        if (groupMatchTarget == GroupMatchTarget.ATTRIBUTE) {
            config.put(GROUP_MATCH_ATTRIBUTE_NAME, resourceMatchAttributeName);
        } else {
            config.remove(GROUP_MATCH_ATTRIBUTE_NAME);
        }

        policy.setConfig(config);
    }
}