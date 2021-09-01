package org.keycloak.authorization.policy.provider.groupmembership;

import static org.keycloak.models.utils.ModelToRepresentation.buildGroupPath;

import java.util.List;
import java.util.function.BiFunction;

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
    private static final String RESOURCE_NAME_PREFIX = "group.resource.";

    private final BiFunction<Policy, AuthorizationProvider, GroupMembershipPolicyRepresentation> representationFunction;

    public GroupMembershipPolicyProvider(BiFunction<Policy, AuthorizationProvider, GroupMembershipPolicyRepresentation> representationFunction) {
        this.representationFunction = representationFunction;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        //https://github.com/keycloak/keycloak/blob/master/services/src/main/java/org/keycloak/services/resources/admin/permissions/GroupPermissions.java
        Resource resource = evaluation.getPermission().getResource();
        if (!"Group".equals(resource.getType())) {
            return;
        }

        String resourceName = resource.getName();
        if (!resourceName.startsWith(RESOURCE_NAME_PREFIX)) {
            return;
        }
        
        String groupId = resourceName.substring(RESOURCE_NAME_PREFIX.length());
        AuthorizationProvider authorizationProvider = evaluation.getAuthorizationProvider();
        RealmModel realm = authorizationProvider.getRealm();
        GroupModel allowedGroup = realm.getGroupById(groupId);
        if (allowedGroup == null) {
            return;
        }
        
        GroupMembershipPolicyRepresentation policy = representationFunction.apply(evaluation.getPolicy(), authorizationProvider);
        Attributes.Entry groupsClaim = evaluation.getContext().getIdentity().getAttributes().getValue(policy.getGroupsClaim());
        if (groupsClaim == null || groupsClaim.isEmpty()) {
            List<String> userGroups = evaluation.getRealm().getUserGroups(evaluation.getContext().getIdentity().getId());
            groupsClaim = new Entry(policy.getGroupsClaim(), userGroups);
        }
        
        for (int i = 0; i < groupsClaim.size(); i++) {
            String group = groupsClaim.asString(i);

            if (group.indexOf('/') != -1) {
                String allowedGroupPath = buildGroupPath(allowedGroup);
                if (group.startsWith(allowedGroupPath)) {
                    evaluation.grant();
                    return;
                }
            }

            // in case the group from the claim does not represent a path, we just check an exact name match
            if (group.equals(allowedGroup.getName())) {
                evaluation.grant();
                return;
            }
        }
    }

    @Override
    public void close() {
    }
}