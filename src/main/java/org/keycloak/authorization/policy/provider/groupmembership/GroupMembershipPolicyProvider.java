package org.keycloak.authorization.policy.provider.groupmembership;

import static org.keycloak.models.utils.ModelToRepresentation.buildGroupPath;

import java.util.Collections;
import java.util.List;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.attribute.Attributes;
import org.keycloak.authorization.attribute.Attributes.Entry;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.policy.evaluation.Evaluation;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.authorization.GroupMembershipPolicyRepresentation;

public class GroupMembershipPolicyProvider implements PolicyProvider {
    private final BiFunction<Policy, AuthorizationProvider, GroupMembershipPolicyRepresentation> representationFunction;

    public GroupMembershipPolicyProvider(
            BiFunction<Policy, AuthorizationProvider, GroupMembershipPolicyRepresentation> representationFunction) {
        this.representationFunction = representationFunction;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        AuthorizationProvider authorizationProvider = evaluation.getAuthorizationProvider();
        GroupMembershipPolicyRepresentation policy = representationFunction.apply(evaluation.getPolicy(),
                authorizationProvider);

        RealmModel realm = authorizationProvider.getRealm();
        List<GroupModel> allowedGroups = matchResourceGroups(evaluation.getPermission().getResource(), realm, policy);
        if (allowedGroups == null) {
            return;
        }

        Attributes.Entry groupsClaim = evaluation.getContext().getIdentity().getAttributes()
                .getValue(policy.getGroupsClaim());
        if (groupsClaim == null || groupsClaim.isEmpty()) {
            List<String> userGroups = evaluation.getRealm()
                    .getUserGroups(evaluation.getContext().getIdentity().getId());
            groupsClaim = new Entry(policy.getGroupsClaim(), userGroups);
        }

        for (GroupModel groupModel : allowedGroups) {
            for (int i = 0; i < groupsClaim.size(); i++) {
                String group = groupsClaim.asString(i);

                if (group.indexOf('/') != -1) {
                    String allowedGroupPath = buildGroupPath(groupModel);
                    if (group.startsWith(allowedGroupPath)) {
                        evaluation.grant();
                        return;
                    }
                }

                // in case the group from the claim does not represent a path, we just check an
                // exact name match
                if (group.equals(groupModel.getName())) {
                    evaluation.grant();
                    return;
                }
            }
        }
    }

    @Override
    public void close() {
    }

    private static List<GroupModel> matchResourceGroups(Resource resource, RealmModel realm,
            GroupMembershipPolicyRepresentation policy) {
        if (policy.getPattern() == null) {
            return null;
        }

        switch (policy.getResourceMatchTarget()) {
            case NAME:
                return matchResourceGroupsByName(resource, realm, policy);
            case URI:
                return matchResourceGroupsByUris(resource, realm, policy);
            case ATTRIBUTE:
                return matchResourceGroupsByAttribute(resource, realm, policy);
            default:
                return null;
        }
    }

    private static List<GroupModel> matchResourceGroupsByName(Resource resource, RealmModel realm,
            GroupMembershipPolicyRepresentation policy) {
        Pattern pattern = Pattern.compile(policy.getPattern());
        Matcher matcher = pattern.matcher(resource.getName());
        return matchGroups(matcher.group(1), realm, policy);
    }

    private static List<GroupModel> matchResourceGroupsByAttribute(Resource resource, RealmModel realm,
            GroupMembershipPolicyRepresentation policy) {
        String attributeName = policy.getGroupMatchAttributeName();
        List<String> attribute = resource.getAttribute(attributeName);
        if (attribute != null) {
            Pattern pattern = Pattern.compile(policy.getPattern());

            for (String value : attribute) {
                Matcher matcher = pattern.matcher(value);
                return matchGroups(matcher.group(1), realm, policy);
            }
        }

        return null;
    }

    private static List<GroupModel> matchResourceGroupsByUris(Resource resource, RealmModel realm,
            GroupMembershipPolicyRepresentation policy) {
        Pattern pattern = Pattern.compile(policy.getPattern());

        for (String uri : resource.getUris()) {
            Matcher matcher = pattern.matcher(uri);

            List<GroupModel> groups = matchGroups(matcher.group(1), realm, policy);
            if (groups != null) {
                return groups;
            }
        }

        return null;
    }

    private static List<GroupModel> matchGroups(String input, RealmModel realm,
            GroupMembershipPolicyRepresentation policy) {
        if (input == null) {
            return null;
        }

        switch (policy.getGroupMatchTarget()) {
            case ID: {
                GroupModel group = realm.getGroupById(input);
                if (group == null) {
                    return null;
                }
                return Collections.singletonList(realm.getGroupById(input));
            }
            case NAME: {
                List<GroupModel> groups = realm.searchForGroupByNameStream(input, -1, -1).collect(Collectors.toList());
                if (groups.size() == 0) {
                    return null;
                }

                return groups;
            }
            case ATTRIBUTE: {
                String attributeName = policy.getGroupMatchAttributeName();
                List<GroupModel> groups = realm.getGroupsStream().filter(group -> {
                    return input.equals(group.getFirstAttribute(attributeName));
                }).collect(Collectors.toList());
                if (groups.size() == 0) {
                    return null;
                }

                return groups;
            }
        }

        return null;
    }
}