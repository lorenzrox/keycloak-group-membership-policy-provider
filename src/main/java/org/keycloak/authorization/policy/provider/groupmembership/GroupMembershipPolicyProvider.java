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
import org.keycloak.models.GroupProvider;
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
        GroupProvider groupProvider = authorizationProvider.getKeycloakSession().groups();
        List<GroupModel> allowedGroups = matchResourceGroups(evaluation.getPermission().getResource(), groupProvider,
                realm, policy);
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
            String allowedGroupPath = buildGroupPath(groupModel);
            for (int i = 0; i < groupsClaim.size(); i++) {
                String group = groupsClaim.asString(i);

                if (group.indexOf('/') != -1) {
                    if (isChildGroupOrSelf(allowedGroupPath, group)) {
                        evaluation.grant();
                        return;
                    }
                }

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

    private static List<GroupModel> matchResourceGroups(Resource resource, GroupProvider groupProvider,
            RealmModel realm, GroupMembershipPolicyRepresentation policy) {
        switch (policy.getResourceMatchTarget()) {
            case NAME:
                return matchResourceGroupsByName(resource, groupProvider, realm, policy);
            case URI:
                return matchResourceGroupsByUris(resource, groupProvider, realm, policy);
            case ATTRIBUTE:
                return matchResourceGroupsByAttribute(resource, groupProvider, realm, policy);
            default:
                return null;
        }
    }

    private static List<GroupModel> matchResourceGroupsByName(Resource resource, GroupProvider groupProvider,
            RealmModel realm, GroupMembershipPolicyRepresentation policy) {
        if (policy.getPattern() == null) {
            return matchGroups(resource.getName(), groupProvider, realm, policy);
        } else {
            Pattern pattern = Pattern.compile(policy.getPattern());
            Matcher matcher = pattern.matcher(resource.getName());
            if (!matcher.matches()) {
                return null;
            }

            return matchGroups(matcher.group(1), groupProvider, realm, policy);
        }
    }

    private static List<GroupModel> matchResourceGroupsByAttribute(Resource resource, GroupProvider groupProvider,
            RealmModel realm, GroupMembershipPolicyRepresentation policy) {
        String attributeName = policy.getGroupMatchAttributeName();
        if (attributeName == null) {
            return null;
        }

        List<String> attribute = resource.getAttribute(attributeName);
        if (attribute != null) {
            if (policy.getPattern() == null) {
                for (String value : attribute) {
                    List<GroupModel> groups = matchGroups(value, groupProvider, realm, policy);
                    if (groups != null) {
                        return groups;
                    }
                }
            } else {
                Pattern pattern = Pattern.compile(policy.getPattern());

                for (String value : attribute) {
                    Matcher matcher = pattern.matcher(value);
                    if (!matcher.matches()) {
                        continue;
                    }

                    List<GroupModel> groups = matchGroups(matcher.group(1), groupProvider, realm, policy);
                    if (groups != null) {
                        return groups;
                    }
                }
            }
        }

        return null;
    }

    private static List<GroupModel> matchResourceGroupsByUris(Resource resource, GroupProvider groupProvider,
            RealmModel realm, GroupMembershipPolicyRepresentation policy) {
        if (policy.getPattern() == null) {
            for (String uri : resource.getUris()) {
                List<GroupModel> groups = matchGroups(uri, groupProvider, realm, policy);
                if (groups != null) {
                    return groups;
                }
            }
        } else {
            Pattern pattern = Pattern.compile(policy.getPattern());

            for (String uri : resource.getUris()) {
                Matcher matcher = pattern.matcher(uri);
                if (!matcher.matches()) {
                    continue;
                }

                List<GroupModel> groups = matchGroups(matcher.group(1), groupProvider, realm, policy);
                if (groups != null) {
                    return groups;
                }
            }
        }

        return null;
    }

    private static List<GroupModel> matchGroups(String input, GroupProvider groupProvider,
            RealmModel realm, GroupMembershipPolicyRepresentation policy) {
        if (input == null) {
            return null;
        }

        switch (policy.getGroupMatchTarget()) {
            case ID: {
                GroupModel group = groupProvider.getGroupById(realm, input);
                if (group == null) {
                    return null;
                }

                return Collections.singletonList(group);
            }
            case NAME: {
                List<GroupModel> groups = groupProvider.searchForGroupByNameStream(realm, input, true, -1, -1)
                        .collect(Collectors.toList());
                if (groups.size() == 0) {
                    return null;
                }

                return groups;
            }
            case ATTRIBUTE: {
                String attributeName = policy.getGroupMatchAttributeName();
                if (attributeName == null) {
                    return null;
                }

                List<GroupModel> groups = groupProvider.getGroupsStream(realm).filter(group -> {
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

    private static boolean isChildGroupOrSelf(String parentGroup, String childGroup) {
        if (childGroup.startsWith(parentGroup)) {
            int length = childGroup.length();
            return length == parentGroup.length() || childGroup.charAt(length - 1) == '/';
        }

        return false;
    }
}