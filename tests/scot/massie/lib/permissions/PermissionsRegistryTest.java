package scot.massie.lib.permissions;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import scot.massie.lib.permissions.exceptions.MissingPermissionException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class PermissionsRegistryTest<TPReg extends PermissionsRegistry<String>>
{
    /*

    Note: Tests that pass for users are expected to pass for groups as well, as they're both implemented using the same
    class. Providing test coverage for both would be needless duplication.

     */

    protected abstract TPReg getNewPermissionsRegistry();
    protected abstract void createUser(TPReg reg, String userId);
    protected abstract void createGroup(TPReg reg, String groupName);
    protected abstract void createGroup(TPReg reg, String groupName, int priority);
    protected abstract void createGroup(TPReg reg, String groupName, double priority);



    //region Method tests
    //region Assertions
    //region Permissions
    //region Has
    // For anything beyond simple "has" or "doesn't have", behvaiour is expected to be comparable to the regular "has
    // permission" methods. So tests are only provided for "has" and "doesn't have".
    @Test
    void assertHasPermission_has()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertDoesNotThrow(() -> reg.assertUserHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    void assertHasPermission_doesntHave()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertThatThrownBy(() -> reg.assertUserHasPermission("user1", "some.permission.foot"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.permission.foot"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.permission.foot"));
    }
    //endregion

    //region Has all
    @Test
    void assertHasAllPermissions_hasNone()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactlyInAnyOrder("some",
                                                                                           "some.permission.doot",
                                                                                           "some.permission.hoot",
                                                                                           "some.other.permission"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isTrue())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse());
    }

    @Test
    void assertHasAllPermissions_hasNoneOfOne()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1", "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactlyInAnyOrder("some.other.permission"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse())
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.permission"));
    }

    @Test
    void assertHasAllPermissions_hasOneOfMultiple()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactlyInAnyOrder("some",
                                                                                           "some.permission.doot",
                                                                                           "some.other.permission"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isTrue())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse());
    }

    @Test
    void assertHasAllPermissions_hasSome()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactlyInAnyOrder("some",
                                                                                           "some.permission.doot"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isTrue())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse());
    }

    @Test
    void assertHasAllPermissions_hasAllButOne()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactlyInAnyOrder("some.permission.doot"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse())
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.permission.doot"));
    }

    @Test
    void assertHasAllPermissions_hasAll()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertDoesNotThrow(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some.permission.hoot",
                                                                 "some.permission.doot",
                                                                 "some.other.permission"));
    }

    @Test
    void assertHasAllPermissions_hasAllOfOne()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertDoesNotThrow(() -> reg.assertUserHasAllPermissions("user1", "some.permission.hoot"));
    }

    //endregion

    //region Has any
    @Test
    void assertHasAnyPermissions_hasNone()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");

        assertThatThrownBy(() -> reg.assertUserHasAnyPermission("user1",
                                                                "some",
                                                                "some.permission.doot",
                                                                "some.permission.hoot",
                                                                "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactlyInAnyOrder("some",
                                                                                           "some.permission.doot",
                                                                                           "some.permission.hoot",
                                                                                           "some.other.permission"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isTrue())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue());
    }

    @Test
    void assertHasAnyPermissions_hasNoneOfOne()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");

        assertThatThrownBy(() -> reg.assertUserHasAnyPermission("user1", "some.permission.doot"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getUserId()).isEqualTo("user1"))
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactlyInAnyOrder("some.permission.doot"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.permission.doot"));
    }

    @Test
    void assertHasAnyPermissions_hasOneOfMultiple()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");

        assertDoesNotThrow(() -> reg.assertUserHasAnyPermission("user1",
                                                                "some",
                                                                "some.permission.doot",
                                                                "some.permission.hoot",
                                                                "some.other.permission"));
    }

    @Test
    void assertHasAnyPermissions_hasSome()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertDoesNotThrow(() -> reg.assertUserHasAnyPermission("user1",
                                                                "some",
                                                                "some.permission.doot",
                                                                "some.permission.hoot",
                                                                "some.other.permission"));
    }

    @Test
    void assertHasAnyPermissions_hasAll()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertDoesNotThrow(() -> reg.assertUserHasAnyPermission("user1",
                                                                "some.permission.doot",
                                                                "some.permission.hoot",
                                                                "some.other.permission"));
    }
    //endregion
    //endregion
    //endregion

    //region Accessors
    //region Permission queries
    //region Get status
    //region Single
    @Test
    public void getPermissionStatus_doesNotHave()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_doesNotHave_hasSubpermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.perm.doot");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_doesNotHave_hasAllSubpermissionsViaWildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.perm.*");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_hasDirectlyExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.perm: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_hasDirectlyUnderOtherWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_hasDirectlyUnderWildcardWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.*: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_hasDirectlyExactlyWithArg_hasDirectlyUnderOtherWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other: My parent perm arg.");
        reg.assignUserPermission("user1", "some.other.perm: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_hasViaGroupExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "some.other.perm: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_hasViaGroupsGroupExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupPermission("group2", "some.other.perm: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_hasViaDefaultsExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignDefaultPermission("some.other.perm: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_hasViaDefaultGroupExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignGroupPermission("group1", "some.other.perm: My perm arg.");
        reg.assignDefaultGroup("group1");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_negatedDirectlyExactly_hasViaGroupExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "some.other.perm: My perm arg.");
        reg.assignUserPermission("user1", "-some.other.perm");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_negatedDirectlyExactly_hasViaDefaultsExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignDefaultPermission("some.other.perm: My perm arg.");
        reg.assignUserPermission("user1", "-some.other.perm");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_negatedViaGroupExactly_hasViaGroupsGroupExactly()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupPermission("group2", "some.other.perm: My perm arg.");
        reg.assignUserPermission("user1", "-some.other.perm");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_negatedViaGroupExactly_hasViaHigherPriorityGroupExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        createGroup(reg, "group1", 10);
        createGroup(reg, "group2", 20);
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");
        reg.assignGroupPermission("group1", "-some.other.perm");
        reg.assignGroupPermission("group2", "some.other.perm: My perm arg.");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isTrue();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isEqualTo("My perm arg.");
        assertDoesNotThrow(ps::assertHasPermission);
    }

    @Test
    public void getPermissionStatus_negatedViaGroupExactly_hasViaLowerPriorityGroupExactlyWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        createGroup(reg, "group1", 10);
        createGroup(reg, "group2", 20);
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");
        reg.assignGroupPermission("group1", "some.other.perm: My perm arg.");
        reg.assignGroupPermission("group2", "-some.other.perm");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_negatedDirectlySubpermission_hasDirectlySuperpermissionWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other: My perm arg.");
        reg.assignUserPermission("user1", "-some.other.perm");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    @Test
    public void getPermissionStatus_negatedDirectlyCoveringWildcard_hasDirectlySameButNotWildcardWithArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other: My perm arg.");
        reg.assignUserPermission("user1", "-some.other.*");

        PermissionStatus ps = reg.getUserPermissionStatus("user1", "some.other.perm");

        assertThat(ps.hasPermission()).isFalse();
        assertThat(ps.getPermission()).isEqualTo("some.other.perm");
        assertThat(ps.getPermissionArg()).isNull();

        assertThatThrownBy(ps::assertHasPermission)
                .isInstanceOf(MissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(MissingPermissionException.class))
                .satisfies(ex -> assertThat(ex.getPermission()).isEqualTo("some.other.perm"))
                .satisfies(ex -> assertThat(ex.multiplePermissionsWereMissing()).isFalse())
                .satisfies(ex -> assertThat(ex.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue())
                .satisfies(ex -> assertThat(ex.getPermissions()).containsExactly("some.other.perm"));
    }

    //endregion

    //region Multiple
    @Test
    void getPermissionStatuses_none()
    {
        TPReg reg = getNewPermissionsRegistry();

        Map<String, PermissionStatus> permStatuses = reg.getUserPermissionStatuses("user1");

        assertThat(permStatuses)
                .isNotNull()
                .isEmpty();
    }

    @Test
    void getPermissionStatuses_single_doesntHave()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.noot: permarg");

        Map<String, PermissionStatus> permStatuses = reg.getUserPermissionStatuses("user1", "some.permission.doot");

        Map<String, PermissionStatus> expectedPermStatuses = new HashMap<>();
        expectedPermStatuses.put("some.permission.doot", new PermissionStatus("some.permission.doot", false, null));

        assertThat(permStatuses)
                .isNotNull()
                .containsExactlyInAnyOrderEntriesOf(expectedPermStatuses);
    }

    @Test
    void getPermissionStatuses_single_has()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot: permarg");

        Map<String, PermissionStatus> permStatuses = reg.getUserPermissionStatuses("user1", "some.permission.doot");

        Map<String, PermissionStatus> expectedPermStatuses = new HashMap<>();
        expectedPermStatuses.put("some.permission.doot", new PermissionStatus("some.permission.doot", true, "permarg"));

        assertThat(permStatuses)
                .isNotNull()
                .containsExactlyInAnyOrderEntriesOf(expectedPermStatuses);
    }

    @Test
    void getPermissionStatuses_multiple_doesntHaveAny()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.noot: permarg");

        Map<String, PermissionStatus> permStatuses = reg.getUserPermissionStatuses("user1",
                                                                                   "some.permission.doot",
                                                                                   "some.permission.hoot",
                                                                                   "some.permission.toot",
                                                                                   "some.permission.joot");

        Map<String, PermissionStatus> expectedPermStatuses = new HashMap<>();
        expectedPermStatuses.put("some.permission.doot", new PermissionStatus("some.permission.doot", false, null));
        expectedPermStatuses.put("some.permission.hoot", new PermissionStatus("some.permission.hoot", false, null));
        expectedPermStatuses.put("some.permission.toot", new PermissionStatus("some.permission.toot", false, null));
        expectedPermStatuses.put("some.permission.joot", new PermissionStatus("some.permission.joot", false, null));

        assertThat(permStatuses)
                .isNotNull()
                .containsExactlyInAnyOrderEntriesOf(expectedPermStatuses);
    }

    @Test
    void getPermissionStatuses_multiple_hasSome()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.noot: permarg");
        reg.assignUserPermission("user1", "some.permission.hoot: otharg");
        reg.assignUserPermission("user1", "some.permission.joot: morarg");

        Map<String, PermissionStatus> permStatuses = reg.getUserPermissionStatuses("user1",
                                                                                   "some.permission.doot",
                                                                                   "some.permission.hoot",
                                                                                   "some.permission.toot",
                                                                                   "some.permission.joot");

        Map<String, PermissionStatus> expectedPermStatuses = new HashMap<>();
        expectedPermStatuses.put("some.permission.doot", new PermissionStatus("some.permission.doot", false, null));
        expectedPermStatuses.put("some.permission.hoot", new PermissionStatus("some.permission.hoot", true, "otharg"));
        expectedPermStatuses.put("some.permission.toot", new PermissionStatus("some.permission.toot", false, null));
        expectedPermStatuses.put("some.permission.joot", new PermissionStatus("some.permission.joot", true, "morarg"));

        assertThat(permStatuses)
                .isNotNull()
                .containsExactlyInAnyOrderEntriesOf(expectedPermStatuses);
    }

    @Test
    void getPermissionStatuses_multiple_hasAll()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.noot: permarg");
        reg.assignUserPermission("user1", "some.permission.doot: somarg");
        reg.assignUserPermission("user1", "some.permission.hoot: otharg");
        reg.assignUserPermission("user1", "some.permission.toot: yetarg");
        reg.assignUserPermission("user1", "some.permission.joot: morarg");

        Map<String, PermissionStatus> permStatuses = reg.getUserPermissionStatuses("user1",
                                                                                   "some.permission.doot",
                                                                                   "some.permission.hoot",
                                                                                   "some.permission.toot",
                                                                                   "some.permission.joot");

        Map<String, PermissionStatus> expectedPermStatuses = new HashMap<>();
        expectedPermStatuses.put("some.permission.doot", new PermissionStatus("some.permission.doot", true, "somarg"));
        expectedPermStatuses.put("some.permission.hoot", new PermissionStatus("some.permission.hoot", true, "otharg"));
        expectedPermStatuses.put("some.permission.toot", new PermissionStatus("some.permission.toot", true, "yetarg"));
        expectedPermStatuses.put("some.permission.joot", new PermissionStatus("some.permission.joot", true, "morarg"));

        assertThat(permStatuses)
                .isNotNull()
                .containsExactlyInAnyOrderEntriesOf(expectedPermStatuses);
    }

    @Test
    void getPermissionStatuses_multiple_hasAllUnderSamePermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission: permarg");

        Map<String, PermissionStatus> permStatuses = reg.getUserPermissionStatuses("user1",
                                                                                   "some.permission.doot",
                                                                                   "some.permission.hoot",
                                                                                   "some.permission.toot",
                                                                                   "some.permission.joot");

        Map<String, PermissionStatus> expectedPermStatuses = new HashMap<>();
        expectedPermStatuses.put("some.permission.doot", new PermissionStatus("some.permission.doot", true, "permarg"));
        expectedPermStatuses.put("some.permission.hoot", new PermissionStatus("some.permission.hoot", true, "permarg"));
        expectedPermStatuses.put("some.permission.toot", new PermissionStatus("some.permission.toot", true, "permarg"));
        expectedPermStatuses.put("some.permission.joot", new PermissionStatus("some.permission.joot", true, "permarg"));

        assertThat(permStatuses)
                .isNotNull()
                .containsExactlyInAnyOrderEntriesOf(expectedPermStatuses);
    }
    //endregion
    //endregion

    //region Has
    //region Normally
    @Test
    public void hasPermission_none()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.shoot"));
    }

    @Test
    public void hasPermission_exact()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_atWildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_underExact()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot.likeanowl"));
    }

    @Test
    public void hasPermission_underWildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot.likeanowl"));
    }

    @Test
    public void hasPermission_overExact()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission"));
    }

    @Test
    public void hasPermission_overWildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission"));
    }

    @Test
    public void hasPermission_root()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", ""));
    }

    @Test
    public void hasPermission_atUniversal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "*");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", ""));
    }

    @Test
    public void hasPermission_underUniversal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "*");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "a.completely.different.perm"));
    }

    @Test
    public void hasPermission_negatedRedundantly_exact()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "-some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_negated_exact()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot.noot"));
    }

    @Test
    public void hasPermission_negated_atWildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot.noot"));
    }

    @Test
    public void hasPermission_negated_underExact()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot.noot.joot"));
    }

    @Test
    public void hasPermission_negated_underWildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot.noot.joot"));
    }

    @Test
    public void hasPermission_negated_overExact()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_negated_overWildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot"));
    }
    //endregion

    //region Via group
    //region 2 level hierarchy
    //region simple case
    @Test
    public void hasPermissionViaGroup()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "europe.france.paris");

        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "-europe.france.paris");

        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_negated()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "-europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_negated_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "-europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "europe.france.paris");

        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_negated_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "-europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "-europe.france.paris");

        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }
    //endregion

    //region user has sub-permission
    @Test
    public void hasPermissionViaGroup_hasSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "europe.france.paris.eiffel");

        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_negatesSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "-europe.france.paris.eiffel");

        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_negated_hasSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("Group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "europe.france.paris.eiffel");

        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroup_negated_negatesSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("Group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "-europe.france.paris.eiffel");

        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
    }
    //endregion

    //region group has universal
    @Test
    public void hasPermissionViaGroup_universal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group1", "*");

        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "africa.egypt.cairo"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroup_universal_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group1", "*");
        reg.assignUserPermission("user1", "europe.france.paris");

        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "africa.egypt.cairo"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroup_universal_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group1", "*");
        reg.assignUserPermission("user1", "-europe.france.paris");

        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "africa.egypt.cairo"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroup_negatedUniversal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group1", "-*");

        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertFalse(reg.userHasPermission("user1", "africa.egypt.cairo"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroup_negatedUniversal_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group1", "-*");

        reg.assignUserPermission("user1", "europe.france.paris");
        reg.assignUserPermission("user1", "africa.egypt.cairo");

        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "africa.egypt.cairo"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroup_negatedUniversal_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group1", "-*");

        reg.assignUserPermission("user1", "-europe.france.paris");
        reg.assignUserPermission("user1", "-africa.egypt.cairo");

        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertFalse(reg.userHasPermission("user1", "africa.egypt.cairo"));
        assertFalse(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "africa.egypt.cairo"));
    }
    //endregion
    //endregion

    //region 3 level hierarchy
    //region simple case
    @Test
    public void hasPermissionViaGroupViaGroup()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "europe.france.paris");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "-europe.france.paris");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negated()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "-europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        assertFalse(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negated_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "-europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "europe.france.paris");

        assertFalse(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negated_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "-europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "-europe.france.paris");

        assertFalse(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }
    //endregion

    //region inheriting group has sub-permission
    @Test
    public void hasPermissionViaGroupViaGroup_hasSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "europe.france.paris.eiffel");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group2", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negatesSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "-europe.france.paris.eiffel");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group2", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negated_hasSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "-europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "europe.france.paris.eiffel");

        assertFalse(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negated_negatesSubPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "-europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "-europe.france.paris.eiffel");

        assertFalse(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.france.paris.eiffel"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris.eiffel"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris.eiffel"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
    }
    //endregion

    //region inherited group has universal
    @Test
    public void hasPermissionViaGroupViaGroup_universal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "*");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group2", "africa.egypt.cairo"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "africa.egypt.cairo"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_universal_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "*");

        reg.assignGroupPermission("group1", "europe.france.paris");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group2", "africa.egypt.cairo"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "africa.egypt.cairo"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_universal_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "*");

        reg.assignGroupPermission("group1", "-europe.france.paris");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group2", "africa.egypt.cairo"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertTrue(reg.groupHasPermission("group1", "africa.egypt.cairo"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertTrue(reg.userHasPermission("user1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negatedUniversal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "-*");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group2", "africa.egypt.cairo"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "africa.egypt.cairo"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negatedUniversal_independentlyHasPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "-*");

        reg.assignGroupPermission("group1", "europe.france.paris");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group2", "africa.egypt.cairo"));
        assertTrue(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "africa.egypt.cairo"));
        assertTrue(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "africa.egypt.cairo"));
    }

    @Test
    public void hasPermissionViaGroupViaGroup_negatedUniversal_negatesPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("group1", "group2");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "europe.austria.vienna");
        reg.assignGroupPermission("group1", "europe.germany.berlin");
        reg.assignGroupPermission("group2", "europe.france.paris");
        reg.assignGroupPermission("group2", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "-*");

        reg.assignGroupPermission("group1", "-europe.france.paris");

        assertTrue(reg.groupHasPermission("group2", "europe.france.paris"));
        assertFalse(reg.groupHasPermission("group2", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group2", "africa.egypt.cairo"));
        assertFalse(reg.groupHasPermission("group1", "europe.france.paris"));
        assertTrue(reg.groupHasPermission("group1", "europe.germany.berlin"));
        assertFalse(reg.groupHasPermission("group1", "africa.egypt.cairo"));
        assertFalse(reg.userHasPermission("user1", "europe.france.paris"));
        assertTrue(reg.userHasPermission("user1", "europe.germany.berlin"));
        assertFalse(reg.userHasPermission("user1", "africa.egypt.cairo"));
    }
    //endregion
    //endregion
    //endregion
    //endregion

    //region Has all
    @Test
    void hasAllPermissions_hasNone()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");

        assertThat(reg.userHasAllPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isFalse();
    }

    @Test
    void hasAllPermissions_hasSome()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertThat(reg.userHasAllPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isFalse();
    }

    @Test
    void hasAllPermissions_hasAllDirectly()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.noot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertThat(reg.userHasAllPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isTrue();
    }

    @Test
    void hasAllPermissions_hasSomeDirectly_restViaGroups()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "some.permission.noot");
        reg.assignGroupPermission("group1", "some.permission.hoot");

        assertThat(reg.userHasAllPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isTrue();
    }

    @Test
    void hasAllPermissions_hasSomeDirectly_restViaDefaults()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignDefaultPermission("some.permission.noot");
        reg.assignDefaultPermission("some.permission.hoot");

        assertThat(reg.userHasAllPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isTrue();
    }

    @Test
    void hasAllPermissions_hasSomeDirectly_restViaSuperpermissions()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignUserPermission("user1", "some.permission");
        reg.assignUserPermission("user1", "some.other.permission");
        reg.assignUserPermission("user1", "yet.another.permission");

        assertThat(reg.userHasAllPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission",
                                             "yet.another.permission"))
                .isTrue();
    }
    //endregion

    //region Has any
    @Test
    void hasAnyPermissions_hasNone()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");

        assertThat(reg.userHasAnyPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isFalse();
    }

    @Test
    void hasAnyPermissions_hasSome()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertThat(reg.userHasAnyPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isTrue();
    }

    @Test
    void hasAnyPermissions_hasAll()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.noot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertThat(reg.userHasAnyPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isTrue();
    }

    @Test
    void hasAnyPermissions_hasSomeViaGroups()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "some.permission.doot");
        reg.assignGroupPermission("group1", "some.other.permission");

        assertThat(reg.userHasAnyPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isTrue();
    }

    @Test
    void hasAnyPermissions_hasSomeViaDefaults()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignDefaultPermission("some.permission.doot");
        reg.assignDefaultPermission("some.other.permission");

        assertThat(reg.userHasAnyPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission"))
                .isTrue();
    }

    @Test
    void hasAnyPermissions_hasSomeViaSuperpermissions()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permission");
        reg.assignUserPermission("user1", "some.permission");

        assertThat(reg.userHasAnyPermissions("user1",
                                             "some.permission.doot",
                                             "some.permission.noot",
                                             "some.permission.hoot",
                                             "some.other.permission",
                                             "yet.another.permission"))
                .isTrue();
    }
    //endregion

    //region Has any subpermission of
    @Test
    public void hasAnySubPermissionOf_none()
    {
        TPReg reg = getNewPermissionsRegistry();
        assertFalse(reg.userHasAnySubPermissionOf("user1", "my.perm"));
    }

    @Test
    public void hasAnySubPermissionOf_direct()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "my.perm");

        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm.here"));
    }

    @Test
    public void hasAnySubPermissionOf_inherited()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "my.perm");

        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm.here"));
    }

    @Test
    public void hasAnySubPermissionOf_negatedSame()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "this.is.a.perm");
        reg.assignUserPermission("user1", "-this.is.a.perm");

        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm.here"));
    }

    @Test
    public void hasAnySubPermissionOf_negatedUnder()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "this.is.a");
        reg.assignUserPermission("user1", "-this.is.a.perm");

        assertTrue(reg.userHasAnySubPermissionOf("user1", "this.is"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "this.is.a"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm.here"));
    }

    @Test
    public void hasAnySubPermissionOf_negatedOver()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "this.is.a");
        reg.assignUserPermission("user1", "-this.is");

        assertFalse(reg.userHasAnySubPermissionOf("user1", "this"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm"));
    }

    @Test
    public void hasAnySubPermissionOf_negatedSameStar()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "this.is.a.perm");
        reg.assignUserPermission("user1", "-this.is.a.perm.*");

        assertTrue(reg.userHasAnySubPermissionOf("user1", "this.is.a"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm.here"));
    }

    @Test
    public void hasAnySubPermissionOf_negatedAboveStar()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "this.is.a.perm");
        reg.assignUserPermission("user1", "-this.is.a.*");

        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm"));
        assertFalse(reg.userHasAnySubPermissionOf("user1", "this.is.a.perm.here"));
    }
    //endregion

    //region Args
    //region simple cases
    @Test
    public void getUserPermissionArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin: doot");

        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.germany.berlin"));
    }

    @Test
    public void getUserPermissionArg_empty()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin:");

        assertEquals("", reg.getUserPermissionArg("user1", "europe.germany.berlin"));
    }

    @Test
    public void getUserPermissionArg_noArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        assertNull(reg.getUserPermissionArg("user1", "europe.germany.berlin"));
    }

    @Test
    public void getUserPermissionArg_noPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        assertNull(reg.getUserPermissionArg("user1", "europe.poland.warsaw"));
    }

    @Test
    public void getUserPermissionArg_universal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignUserPermission("user1", "*: doot");

        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.poland.warsaw"));
        assertNull(reg.getUserPermissionArg("user1", "europe.germany.berlin"));
    }
    //endregion

    //region across hierarchy
    @Test
    public void getUserPermissionArg_acrossHierarchy()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        reg.assignUserPermission("user1", "europe.france: doot");
        reg.assignUserPermission("user1", "europe.france.paris: hoot");
        reg.assignUserPermission("user1", "europe.france.paris.eiffel: noot");

        reg.assignUserPermission("user1", "europe.italy: poot");

        assertNull(reg.getUserPermissionArg("user1", "europe"));
        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.france"));
        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe.france.paris"));
        assertEquals("noot", reg.getUserPermissionArg("user1", "europe.france.paris.eiffel"));
        assertEquals("poot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("poot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
        assertEquals("poot", reg.getUserPermissionArg("user1", "europe.italy.rome.vatican"));
    }

    @Test
    public void getUserPermissionArg_acrossHierarchy_negatingMiddle()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        reg.assignUserPermission("user1", "europe.france: doot");
        reg.assignUserPermission("user1", "-europe.france.paris");
        reg.assignUserPermission("user1", "europe.france.paris.eiffel: noot");

        reg.assignUserPermission("user1", "europe.italy: poot");
        reg.assignUserPermission("user1", "-europe.italy.rome");
        reg.assignUserPermission("user1", "europe.italy.rome.vatican");

        assertNull(reg.getUserPermissionArg("user1", "europe"));
        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.france"));
        assertNull(reg.getUserPermissionArg("user1", "europe.france.paris"));
        assertEquals("noot", reg.getUserPermissionArg("user1", "europe.france.paris.eiffel"));
        assertEquals("poot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertNull(reg.getUserPermissionArg("user1", "europe.italy.rome"));
        assertNull(reg.getUserPermissionArg("user1", "europe.italy.rome.vatican"));
    }

    @Test
    public void getUserPermissionArg_acrossHierarchy_withUniversal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        reg.assignUserPermission("user1", "*: soot");

        reg.assignUserPermission("user1", "europe.france: doot");
        reg.assignUserPermission("user1", "europe.france.paris: hoot");

        assertEquals("soot", reg.getUserPermissionArg("user1", ""));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe"));
        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.france"));
        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe.france.paris"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
    }

    @Test
    public void getUserPermissionArg_acrossHierarchy_withUniversalAndNegatingMiddle()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        reg.assignUserPermission("user1", "*: soot");

        reg.assignUserPermission("user1", "-europe.france");
        reg.assignUserPermission("user1", "europe.france.paris: hoot");

        reg.assignUserPermission("user1", "-europe.italy");
        reg.assignUserPermission("user1", "europe.italy.rome");

        assertEquals("soot", reg.getUserPermissionArg("user1", ""));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe"));
        assertNull(reg.getUserPermissionArg("user1", "europe.france"));
        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe.france.paris"));
        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe.france.paris.eiffel"));
        assertNull(reg.getUserPermissionArg("user1", "europe.italy"));
        assertNull(reg.getUserPermissionArg("user1", "europe.italy.rome"));
        assertNull(reg.getUserPermissionArg("user1", "europe.italy.rome.vatican"));
    }
    //endregion

    //region overwriting
    @Test
    public void getUserPermissionArg_overwriting_notOverwritten()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris: doot");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.france.paris"));
    }

    @Test
    public void getUserPermissionArg_overwriting_notOverwrittenTwice()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
    }

    @Test
    public void getUserPermissionArg_overwriting_negated()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris: doot");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "-europe.france.paris");

        assertNull(reg.getUserPermissionArg("user1", "europe.france.paris"));
    }

    @Test
    public void getUserPermissionArg_overwriting_negatedBySubGroup()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group1", "-europe.italy.rome");

        assertNull(reg.getUserPermissionArg("user1", "europe.italy.rome"));
    }

    @Test
    public void getUserPermissionArg_overwriting_different()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris: doot");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "europe.france.paris: hoot");

        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe.france.paris"));
    }

    @Test
    public void getUserPermissionArg_overwriting_subgroupNegatesUserDifferent()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group1", "-europe.italy.rome");
        reg.assignUserPermission("user1", "europe.italy.rome: hoot");

        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
    }

    @Test
    public void getUserPermissionArg_overwriting_noArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignUserPermission("user1", "europe.france.paris");

        assertNull(reg.getUserPermissionArg("user1", "europe.france.paris"));
    }

    @Test
    public void getUserPermissionArg_overwriting_subgroupNegatesUserNoArg()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");

        reg.assignGroupPermission("group1", "-europe.italy.rome");
        reg.assignUserPermission("user1", "europe.italy.rome");

        assertNull(reg.getUserPermissionArg("user1", "europe.italy.rome"));
    }
    //endregion

    //region overwriting across hierarchy
    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userHighest()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group1", "europe.italy: hoot");
        reg.assignUserPermission("user1", "europe: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe"));
    }

    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userLowest()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "europe: doot");
        reg.assignGroupPermission("group1", "europe.italy: hoot");
        reg.assignUserPermission("user1", "europe.italy.rome: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("doot", reg.getUserPermissionArg("user1", "europe"));
    }

    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userHighestWithNegation()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group1", "-europe.italy");
        reg.assignUserPermission("user1", "europe: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe"));
    }

    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userLowestWithNegation()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "europe: doot");
        reg.assignGroupPermission("group1", "-europe.italy");
        reg.assignUserPermission("user1", "europe.italy.rome: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy.rome"));
        assertNull(reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("doot", reg.getUserPermissionArg("user1", "europe"));
    }

    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userHighestWithUniversal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "europe.italy: doot");
        reg.assignGroupPermission("group1", "europe: hoot");
        reg.assignUserPermission("user1", "*: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe"));
        assertEquals("soot", reg.getUserPermissionArg("user1", ""));
    }

    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userLowestWithUniversal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "*: doot");
        reg.assignGroupPermission("group1", "europe: hoot");
        reg.assignUserPermission("user1", "europe.italy: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("hoot", reg.getUserPermissionArg("user1", "europe"));
        assertEquals("doot", reg.getUserPermissionArg("user1", ""));
    }

    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userHighestWithUniversalAndNegation()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "europe.italy: doot");
        reg.assignGroupPermission("group1", "-europe");
        reg.assignUserPermission("user1", "*: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertEquals("soot", reg.getUserPermissionArg("user1", "europe"));
        assertEquals("soot", reg.getUserPermissionArg("user1", ""));
    }

    @Test
    public void getUserPermissionArg_overwritingAcrossHierarchy_userLowestWithUniversalAndNegation()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToGroup("group1", "group2");
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");
        reg.assignGroupPermission("group1", "europe.france.paris");
        reg.assignGroupPermission("group1", "europe.spain.madrid");
        reg.assignGroupPermission("group2", "europe.italy.rome: doot");
        reg.assignGroupPermission("group2", "europe.poland.warsaw");

        reg.assignGroupPermission("group2", "*: doot");
        reg.assignGroupPermission("group1", "-europe");
        reg.assignUserPermission("user1", "europe.italy: soot");

        assertEquals("soot", reg.getUserPermissionArg("user1", "europe.italy"));
        assertNull(reg.getUserPermissionArg("user1", "europe"));
        assertEquals("doot", reg.getUserPermissionArg("user1", ""));
    }
    //endregion
    //endregion
    //endregion

    //region Group queries
    //region Has
    @Test
    public void hasGroup()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("red", "blue");
        reg.assignGroupToGroup("green", "red");
        reg.assignGroupToGroup("cyan", "green");
        createGroup(reg, "yellow");
        reg.assignGroupToUser("user1", "green");

        assertFalse(reg.userHasGroup("user1", "cyan"));
        assertTrue(reg.userHasGroup("user1", "green"));
        assertTrue(reg.userHasGroup("user1", "red"));
        assertTrue(reg.userHasGroup("user1", "blue"));
        assertFalse(reg.userHasGroup("user1", "yellow"));
    }
    //endregion

    //region Has all
    @Test
    void hasAllGroups_none()
    {
        TPReg reg = getNewPermissionsRegistry();

        assertThat(reg.userHasAllGroups("user1", "group1", "group2", "group3", "group4"))
                .isFalse();
    }

    @Test
    void hasAllGroups_some()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");

        assertThat(reg.userHasAllGroups("user1", "group1", "group2", "group3", "group4"))
                .isFalse();
    }

    @Test
    void hasAllGroups_all()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");
        reg.assignGroupToUser("user1", "group3");
        reg.assignGroupToUser("user1", "group4");

        assertThat(reg.userHasAllGroups("user1", "group1", "group2", "group3", "group4"))
                .isTrue();
    }

    @Test
    void hasAllGroups_allViaOtherGroups()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");
        reg.assignGroupToGroup("group2", "group3");
        reg.assignGroupToGroup("group2", "group4");

        assertThat(reg.userHasAllGroups("user1", "group1", "group2", "group3", "group4"))
                .isTrue();
    }

    @Test
    void hasAllGroups_allViaDefaults()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");
        reg.assignDefaultGroup("group3");
        reg.assignDefaultGroup("group4");

        assertThat(reg.userHasAllGroups("user1", "group1", "group2", "group3", "group4"))
                .isTrue();
    }

    //endregion

    //region Has any
    @Test
    void hasAnyGroups_none()
    {
        TPReg reg = getNewPermissionsRegistry();

        assertThat(reg.userHasAnyGroups("user1", "group1", "group2", "group3", "group4"))
                .isFalse();
    }

    @Test
    void hasAnyGroups_some()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");

        assertThat(reg.userHasAnyGroups("user1", "group1", "group2", "group3", "group4"))
                .isTrue();
    }

    @Test
    void hasAnyGroups_someViaDefaults()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultGroup("group1");
        reg.assignDefaultGroup("group2");

        assertThat(reg.userHasAnyGroups("user1", "group1", "group2", "group3", "group4"))
                .isTrue();
    }

    @Test
    void hasAnyGroups_all()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupToUser("user1", "group2");
        reg.assignGroupToUser("user1", "group3");
        reg.assignGroupToUser("user1", "group4");

        assertThat(reg.userHasAnyGroups("user1", "group1", "group2", "group3", "group4"))
                .isTrue();
    }

    //endregion
    //endregion

    //region State

    //endregion

    //region Getters
    //region Members
    //endregion

    //region Group priorities

    // TO DO: Write tests here.

    //endregion

    //region Permissions
    @Test
    public void getUsers_empty()
    {
        TPReg reg = getNewPermissionsRegistry();
        assertThat(reg.getUsers()).isEmpty();
    }

    @Test
    public void getUsers()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("userdoot", "my.first.perm");
        reg.assignUserPermission("userhoot", "my.second.perm");
        reg.assignUserPermission("usernoot", "my.third.perm");

        assertThat(reg.getUsers())
                .containsExactlyInAnyOrderElementsOf(Arrays.asList("userdoot", "userhoot", "usernoot"));
    }
    //endregion

    //region Permissions and statuses

    @Test
    void getAllPermissionStatuses_userDoesntExist()
    {
        TPReg reg = getNewPermissionsRegistry();

        Collection<PermissionStatus> pstatuses = reg.getAllUserPermissionStatuses("user1");

        assertThat(pstatuses).isEmpty();
    }

    @Test
    void getAllPermissionStatuses_userHasNone()
    {
        TPReg reg = getNewPermissionsRegistry();
        createUser(reg, "user1");

        Collection<PermissionStatus> pstatuses = reg.getAllUserPermissionStatuses("user1");

        assertThat(pstatuses).isEmpty();
    }

    @Test
    void getAllPermissionStatuses_userHasSomeDirectly()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission");
        reg.assignUserPermission("user1", "some.other.permission");
        reg.assignUserPermission("user1", "yet.another.permission");

        assertThat(reg.getAllUserPermissionStatuses("user1"))
                .containsExactlyInAnyOrder(new PermissionStatus("some.permission",        true, null),
                                           new PermissionStatus("some.other.permission",  true, null),
                                           new PermissionStatus("yet.another.permission", true, null));
    }

    @Test
    void getAllPermissionStatuses_userHasSomeViaGroup()
    {
        // This method shouldn't include permissions a user has indirectly.

        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "some.permission");
        reg.assignGroupPermission("group1", "some.other.permission");
        reg.assignGroupPermission("group1", "yet.another.permission");

        assertThat(reg.getAllUserPermissionStatuses("user1")).isEmpty();
    }

    @Test
    void getAllPermissionStatuses_userHasSomeViaDefaults()
    {
        // This method shouldn't include permissions a user has indirectly.

        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignDefaultPermission("some.permission");
        reg.assignDefaultPermission("some.other.permission");
        reg.assignDefaultPermission("yet.another.permission");

        assertThat(reg.getAllUserPermissionStatuses("user1")).isEmpty();
    }

    //endregion

    //region Groups
    @Test
    public void getGroupNames_empty()
    {
        TPReg reg = getNewPermissionsRegistry();
        assertThat(reg.getGroupNames()).isEmpty();
    }

    @Test
    public void getGroupNames()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupPermission("groupdoot", "my.first.perm");
        reg.assignGroupPermission("grouphoot", "my.second.perm");
        reg.assignGroupPermission("groupnoot", "my.third.perm");

        assertThat(reg.getGroupNames())
                .containsExactlyInAnyOrderElementsOf(Arrays.asList("groupdoot", "grouphoot", "groupnoot"));
    }
    //endregion

    //region PermissionGroups
    @Test
    public void getPermissions_noUser()
    {
        TPReg reg = getNewPermissionsRegistry();
        assertThat(reg.getUserPermissions("nonexistentuser")).isEmpty();
    }

    @Test
    public void getPermissions()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("userdoot", "europe.france.paris");
        reg.assignUserPermission("userhoot", "europe.germany.berlin");
        reg.assignUserPermission("userhoot", "europe.greece.athens");
        reg.assignUserPermission("userhoot", "europe.netherlands.amsterdam");
        reg.assignUserPermission("usernoot", "europe.spain.madrid");

        assertThat(reg.getUserPermissions("userhoot"))
                .containsExactlyInAnyOrderElementsOf(Arrays.asList("europe.germany.berlin",
                                                                   "europe.greece.athens",
                                                                   "europe.netherlands.amsterdam"));
    }

    @Test
    public void getPermissions_withNegating()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("userdoot", "europe.france.paris");
        reg.assignUserPermission("userhoot", "europe.germany.berlin");
        reg.assignUserPermission("userhoot", "-europe.greece.athens");
        reg.assignUserPermission("userhoot", "europe.netherlands.amsterdam");
        reg.assignUserPermission("usernoot", "europe.spain.madrid");

        assertThat(reg.getUserPermissions("userhoot"))
                .containsExactlyInAnyOrderElementsOf(Arrays.asList("europe.germany.berlin",
                                                                   "-europe.greece.athens",
                                                                   "europe.netherlands.amsterdam"));
    }

    @Test
    public void getPermissions_withArgs()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("userdoot", "europe.france.paris");
        reg.assignUserPermission("userhoot", "europe.germany.berlin");
        reg.assignUserPermission("userhoot", "europe.greece.athens: Where the parthenon is");
        reg.assignUserPermission("userhoot", "europe.netherlands.amsterdam");
        reg.assignUserPermission("usernoot", "europe.spain.madrid");

        assertThat(reg.getUserPermissions("userhoot"))
                .containsExactlyInAnyOrderElementsOf(Arrays.asList("europe.germany.berlin",
                                                                   "europe.greece.athens",
                                                                   "europe.netherlands.amsterdam"));
    }
    //endregion
    //endregion
    //endregion

    //region Mutators
    //region Absorb

    // TO DO: Write tests here.

    //endregion

    //region Permissions
    //region Assign
    //region Single
    @Test
    public void assignPermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    some.other.permission\n    some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_negating()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "-some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    some.other.permission\n    -some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_wildcard()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    some.other.permission\n    some.permission.doot.*";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_universal()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "*");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    *\n    some.other.permission\n    some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_universalNegating()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "-*");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    -*\n    some.other.permission\n    some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermissionToGroup()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupPermission("group1", "some.permission.doot");
        reg.assignGroupPermission("group1", "some.other.permission");

        String expectedResult = "group1\n    some.other.permission\n    some.permission.doot";
        assertEquals("", reg.usersToSaveString());
        assertEquals(expectedResult, reg.groupsToSaveString());
    }
    //endregion

    //region Multiple

    // TO DO: Write tests here.

    //endregion
    //endregion

    //region Revoke
    @Test
    public void revokePermission()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        reg.revokeUserPermission("user1", "some.permission.hoot");

        String expectedResult = "user1\n    some.other.permission\n    some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }
    //endregion
    //endregion

    //region Groups
    //region Assign
    //region Single
    @Test
    public void assignGroupToUser()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");
        reg.assignGroupToUser("user1", "turtles");
        reg.assignGroupToUser("user1", "ducks");

        String expectedResult =     "user1"
                                    + "\n    #ducks"
                                    + "\n    #turtles"
                                    + "\n    some.other.permission"
                                    + "\n    some.permission.doot"
                                    + "\n    some.permission.hoot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignGroupToGroup()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignGroupPermission("group1", "some.permission.hoot");
        reg.assignGroupPermission("group1", "some.other.permission");
        reg.assignGroupToGroup("group1", "turtles");
        reg.assignGroupToGroup("group1", "ducks");

        String expectedUsers = "user1\n    some.permission.doot";
        String expectedGroups =   "ducks\n\n"
                                  + "group1\n"
                                  + "    #ducks\n"
                                  + "    #turtles\n"
                                  + "    some.other.permission\n"
                                  + "    some.permission.hoot\n\n"
                                  + "turtles";

        assertEquals(expectedUsers, reg.usersToSaveString());
        assertEquals(expectedGroups, reg.groupsToSaveString());
    }
    //endregion

    //region Multiple

    // TO DO: Write tests here.

    //endregion
    //endregion

    //region Revoke
    @Test
    void revokeGroupFromUser_had()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        assertThat(reg.userHasGroup("user1", "group1"))
                .withFailMessage("Failed initial test set-up - .userHasGroup did not return true after assigning the "
                                 + "group to the user.")
                .isTrue();

        assertThat(reg.revokeGroupFromUser("user1", "group1")).isTrue();
        assertThat(reg.userHasGroup("user1", "group1")).isFalse();
    }

    @Test
    void revokeGroupFromUser_didntHave()
    {
        TPReg reg = getNewPermissionsRegistry();
        assertThat(reg.userHasGroup("user1", "group1"))
                .withFailMessage("Failed initial test set-up - .userHasGroup did not return false despite having not "
                                 + "assigned the group to the user.")
                .isFalse();

        assertThat(reg.revokeGroupFromUser("user1", "group1")).isFalse();
        assertThat(reg.userHasGroup("user1", "group1")).isFalse();
    }

    @Test
    void revokeGroupFromGroup_had()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("subgroup", "supergroup");
        assertThat(reg.groupExtendsFromGroup("subgroup", "supergroup"))
                .withFailMessage("Failed initial test set-up - .groupExtendsFromGroup did not return true after "
                                 + "assigning the supergroup to the subgroup.")
                .isTrue();

        assertThat(reg.revokeGroupFromGroup("subgroup", "supergroup")).isTrue();
        assertThat(reg.groupExtendsFromGroup("user1", "group1")).isFalse();
    }

    @Test
    void revokeGroupFromGroup_didntHave()
    {
        TPReg reg = getNewPermissionsRegistry();
        assertThat(reg.groupExtendsFromGroup("subgroup", "supergroup"))
                .withFailMessage("Failed initial test set-up - .groupExtendsFromGroup did not return false despite "
                                 + "having not assigned the supergroup to the subgroup.")
                .isFalse();

        assertThat(reg.revokeGroupFromGroup("subgroup", "supergroup")).isFalse();
        assertThat(reg.groupExtendsFromGroup("subgroup", "supergroup")).isFalse();
    }
    //endregion
    //endregion

    //region Clear
    @Test
    void clear_empty()
    {
        TPReg reg = getNewPermissionsRegistry();

        reg.clear();

        assertThat(reg.getUsers()).isEmpty();
        assertThat(reg.getGroupNames()).isEmpty();
        assertThat(reg.getDefaultPermissions()).isEmpty();
    }

    @Test
    void clear_onlyHadUsers()
    {
        TPReg reg = getNewPermissionsRegistry();
        createUser(reg, "doot");
        createUser(reg, "noot");
        createUser(reg, "hoot");

        reg.clear();

        assertThat(reg.getUsers()).isEmpty();
        assertThat(reg.getGroupNames()).isEmpty();
        assertThat(reg.getDefaultPermissions()).isEmpty();
    }

    @Test
    void clear_onlyHadGroups()
    {
        TPReg reg = getNewPermissionsRegistry();
        createGroup(reg, "doot");
        createGroup(reg, "noot");
        createGroup(reg, "hoot");

        reg.clear();

        assertThat(reg.getUsers()).isEmpty();
        assertThat(reg.getGroupNames()).isEmpty();
        assertThat(reg.getDefaultPermissions()).isEmpty();
    }

    @Test
    void clear_onlyHadDefaults()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("some.permission.doot");
        reg.assignDefaultPermission("some.permission.noot");
        reg.assignDefaultPermission("some.other.permission");
        reg.assignDefaultPermission("yet.another.permission");

        reg.clear();

        assertThat(reg.getUsers()).isEmpty();
        assertThat(reg.getGroupNames()).isEmpty();
        assertThat(reg.getDefaultPermissions()).isEmpty();
    }

    @Test
    void clear_hadUsersGroupsAndDefaults()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "some.permission.noot");
        reg.assignDefaultPermission("some.other.permission");
        reg.assignDefaultGroup("group2");
        reg.assignGroupPermission("group2", "yet.another.permission");
        reg.assignGroupToGroup("group1", "group3");
        reg.assignGroupPermission("group3", "some.other.unrelated.permission");

        reg.clear();

        assertThat(reg.getUsers()).isEmpty();
        assertThat(reg.getGroupNames()).isEmpty();
        assertThat(reg.getDefaultPermissions()).isEmpty();
    }
    //endregion

    //region Set flags

    //endregion
    //endregion

    //region Saving & Loading
    //region Saving
    @Test
    public void singleLine_saving()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignGroupPermission("yellow", "permission.to.yellow");
        reg.assignGroupToGroup("red", "yellow");
        reg.assignGroupToGroup("blue", "red");

        String expected = "blue #red\nred #yellow\n\nyellow\n    permission.to.yellow";
        assertEquals(expected, reg.groupsToSaveString());
    }
    //endregion

    //region Loading
    @Test
    public void singleLine_loading() throws IOException
    {
        TPReg reg = getNewPermissionsRegistry();
        String saveString =   "blue #red"
                              + "\nred: 5 #yellow"
                              + "\n\nyellow"
                              + "\n    permission.from.yellow";

        reg.loadGroupsFromSaveString(saveString);

        assertThat(reg.getGroupNames()).containsExactlyInAnyOrderElementsOf(Arrays.asList("blue", "red", "yellow"));
        assertTrue(reg.groupHasPermission("yellow", "permission.from.yellow"));
        assertTrue(reg.groupHasPermission("red", "permission.from.yellow"));
        assertTrue(reg.groupHasPermission("blue", "permission.from.yellow"));

        assertEquals(saveString, reg.groupsToSaveString());
    }

    @Test
    public void multilinePermissionArgsLoaded()
    {
        TPReg reg = getNewPermissionsRegistry();

        String saveString = "group1\n"
                            + "    my.perm.first\n"
                            + "    my.perm.second: this is\n"
                            + "        some text\n"
                            + "        that should be written\n"
                            + "    my.perm.third";

        String expectedPermissionArg = "this is\nsome text\nthat should be written";

        try
        { reg.loadGroupsFromSaveString(saveString); }
        catch(IOException e)
        { e.printStackTrace(); }

        assertEquals(expectedPermissionArg, reg.getGroupPermissionArg("group1", "my.perm.second"));

        saveString = "group1\n"
                     + "    my.perm.first\n"
                     + "    my.perm.second:\n"
                     + "        this is\n"
                     + "        some text\n"
                     + "        that should be written\n"
                     + "    my.perm.third";

        try
        { reg.loadGroupsFromSaveString(saveString); }
        catch(IOException e)
        { e.printStackTrace(); }

        assertEquals(expectedPermissionArg, reg.getGroupPermissionArg("group1", "my.perm.second"));
    }
    //endregion

    //region Both
    @Test
    public void multilinePermissionArgLoadAndSave()
    {
        TPReg reg = getNewPermissionsRegistry();

        String saveString = "group1\n"
                            + "    my.perm.first\n"
                            + "    my.perm.second: this is\n"
                            + "        some text\n"
                            + "        that should be written\n"
                            + "    my.perm.third";

        try
        { reg.loadGroupsFromSaveString(saveString); }
        catch(IOException e)
        { e.printStackTrace(); }

        String expectedResult = "group1\n"
                                + "    my.perm.first\n"
                                + "    my.perm.second:\n"
                                + "        this is\n"
                                + "        some text\n"
                                + "        that should be written\n"
                                + "    my.perm.third";

        assertEquals(expectedResult, reg.groupsToSaveString());
    }

    @Test
    public void defaultPermissions_loadingAndSaving()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("this.is.a.permission");
        reg.assignDefaultPermission("this.is.another.permission: 5");
        reg.assignDefaultGroup("somedefaultgroup");

        String expectedGroupSavestring = "*"
                                         + "\n    #somedefaultgroup"
                                         + "\n    this.is.a.permission"
                                         + "\n    this.is.another.permission: 5"
                                         + "\n"
                                         + "\nsomedefaultgroup";

        assertEquals(expectedGroupSavestring, reg.groupsToSaveString());
    }
    //endregion
    //endregion
    //endregion

    //region Additional tests
    //region group priority
    @Test
    public void groupPriority_saving()
    {
        TPReg reg = getNewPermissionsRegistry();
        createGroup(reg, "katara", 5);
        createGroup(reg, "iroh", -3.76);
        createGroup(reg, "azula", -3.4);
        createGroup(reg, "suki", -3.9);
        createGroup(reg, "appa", -3);
        createGroup(reg, "momo", -4);
        createGroup(reg, "jet", 4.2);
        createGroup(reg, "sozin", 2.5);

        reg.assignGroupPermission("katara", "someperm: doot");
        reg.assignGroupPermission("momo", "someperm: moot");
        reg.assignGroupPermission("iroh", "someperm: foot");
        reg.assignGroupPermission("suki", "someperm: poot");
        reg.assignGroupPermission("sozin", "someperm: goot");
        reg.assignGroupPermission("jet", "someperm: voot");
        reg.assignGroupPermission("azula", "someperm: noot");
        reg.assignGroupPermission("appa", "someperm: joot");

        String expected = "appa: -3\n    someperm: joot\n\n"
                          + "azula: -3.4\n    someperm: noot\n\n"
                          + "iroh: -3.76\n    someperm: foot\n\n"
                          + "jet: 4.2\n    someperm: voot\n\n"
                          + "katara: 5\n    someperm: doot\n\n"
                          + "momo: -4\n    someperm: moot\n\n"
                          + "sozin: 2.5\n    someperm: goot\n\n"
                          + "suki: -3.9\n    someperm: poot";

        assertEquals(expected, reg.groupsToSaveString());
    }

    @Test
    public void groupPriority_order()
    {
        TPReg reg = getNewPermissionsRegistry();
        createGroup(reg, "katara", 5);
        createGroup(reg, "iroh", -3.76);
        createGroup(reg, "azula", -3.4);
        createGroup(reg, "suki", -3.9);
        createGroup(reg, "appa", -3);
        createGroup(reg, "momo", -4);
        createGroup(reg, "jet", 4.2);
        createGroup(reg, "sozin", 2.5);

        reg.assignGroupToUser("user1", "katara");
        reg.assignGroupToUser("user1", "iroh");
        reg.assignGroupToUser("user1", "azula");
        reg.assignGroupToUser("user1", "suki");
        reg.assignGroupToUser("user1", "appa");
        reg.assignGroupToUser("user1", "momo");
        reg.assignGroupToUser("user1", "jet");
        reg.assignGroupToUser("user1", "sozin");

        reg.assignGroupPermission("momo", "someperm: moot");
        reg.assignGroupPermission("suki", "someperm: poot");

        assertEquals("poot", reg.getUserPermissionArg("user1", "someperm"));

        reg.assignGroupPermission("azula", "someperm: noot");
        reg.assignGroupPermission("iroh", "someperm: foot");

        assertEquals("noot", reg.getUserPermissionArg("user1", "someperm"));

        reg.assignGroupPermission("katara", "someperm: doot");
        reg.assignGroupPermission("appa", "someperm: joot");

        assertEquals("doot", reg.getUserPermissionArg("user1", "someperm"));

        reg.assignGroupPermission("sozin", "someperm: goot");
        reg.assignGroupPermission("jet", "someperm: voot");

        assertEquals("doot", reg.getUserPermissionArg("user1", "someperm"));
    }

    @Test
    public void groupPriority_inferredOrder()
    {
        // secondary priority inferred from alphabetical order.

        TPReg reg = getNewPermissionsRegistry();
        createGroup(reg, "katara");
        createGroup(reg, "iroh");
        createGroup(reg, "azula");
        createGroup(reg, "suki");
        createGroup(reg, "appa");
        createGroup(reg, "momo");
        createGroup(reg, "jet");
        createGroup(reg, "sozin");
        createGroup(reg, "toph", 2);
        createGroup(reg, "boulder", 2);

        reg.assignGroupToUser("user1", "katara");
        reg.assignGroupToUser("user1", "iroh");
        reg.assignGroupToUser("user1", "azula");
        reg.assignGroupToUser("user1", "suki");
        reg.assignGroupToUser("user1", "appa");
        reg.assignGroupToUser("user1", "momo");
        reg.assignGroupToUser("user1", "jet");
        reg.assignGroupToUser("user1", "sozin");
        reg.assignGroupToUser("user1", "toph");
        reg.assignGroupToUser("user1", "boulder");

        reg.assignGroupPermission("suki", "someperm: moot");
        reg.assignGroupPermission("sozin", "someperm: poot");

        assertEquals("poot", reg.getUserPermissionArg("user1", "someperm"));

        reg.assignGroupPermission("katara", "someperm: noot");
        reg.assignGroupPermission("momo", "someperm: foot");

        assertEquals("noot", reg.getUserPermissionArg("user1", "someperm"));

        reg.assignGroupPermission("appa", "someperm: doot");
        reg.assignGroupPermission("azula", "someperm: joot");

        assertEquals("doot", reg.getUserPermissionArg("user1", "someperm"));

        reg.assignGroupPermission("iroh", "someperm: goot");
        reg.assignGroupPermission("jet", "someperm: voot");

        assertEquals("doot", reg.getUserPermissionArg("user1", "someperm"));

        reg.assignGroupPermission("boulder", "someperm: zoot");
        reg.assignGroupPermission("toph", "someperm: yoot");

        assertEquals("zoot", reg.getUserPermissionArg("user1", "someperm"));
    }

    @Test
    public void priorityRetainedForGroupsUsedBeforeDeclared()
    {
        TPReg reg = getNewPermissionsRegistry();
        String saveString = "group1\n    #group2\n    some.other.permission\n\ngroup2: 3\n    some.permission.here";

        try
        { reg.loadGroupsFromSaveString(saveString); }
        catch(IOException e)
        { e.printStackTrace(); }

        assertEquals(saveString, reg.groupsToSaveString());
    }
    //endregion

    //region Default permissions
    @Test
    public void defaultPermissions_fallingBack_otherwiseEmpty()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("this.is.a.permission");
        assertTrue(reg.userHasPermission("toodles", "this.is.a.permission.too"));
    }

    @Test
    public void defaultPermissions_fallingBack_onExistingUser()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("this.is.a.permission: 5");
        reg.assignDefaultPermission("this.is.another.permission: 6");
        reg.assignUserPermission("toodles", "this.is.a: 7");
        assertEquals("7", reg.getUserPermissionArg("toodles", "this.is.a.permission"));
        assertEquals("6", reg.getUserPermissionArg("toodles", "this.is.another.permission"));
    }

    @Test
    public void defaultPermissions_fallingBack_toDefaultGroup()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultGroup("mygroup");
        reg.assignGroupPermission("mygroup", "this.is.a: 5");
        reg.assignGroupPermission("mygroup", "this.is.another.permission: 6");
        reg.assignGroupPermission("mygroup", "third.permission: 7");
        reg.assignDefaultPermission("this.is.another: 8");
        reg.assignUserPermission("toodles", "this.is.a.permission: 9");

        assertEquals("5", reg.getUserPermissionArg("toodles", "this.is.a"));
        assertEquals("9", reg.getUserPermissionArg("toodles", "this.is.a.permission"));
        assertEquals("8", reg.getUserPermissionArg("toodles", "this.is.another.permission"));
        assertEquals("8", reg.getUserPermissionArg("toodles", "this.is.another"));
        assertEquals("7", reg.getUserPermissionArg("toodles", "third.permission"));
    }

    @Test
    public void defaultPermissions_group_nonexisting()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("first.second.third: doot");
        reg.assignDefaultGroup("thedefaultgroup");

        assertFalse(reg.groupHasPermission("testgroup", "first.second.third"));
        assertNull(reg.getGroupPermissionArg("testgroup", "first.second.third"));
        assertFalse(reg.groupExtendsFromGroup("testgroup", "thedefaultgroup"));
    }

    @Test
    public void defaultPermissions_group_existing()
    {
        TPReg reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("first.second.third: doot");
        reg.assignDefaultGroup("thedefaultgroup");
        reg.assignGroupPermission("testgroup", "another.permission");

        assertFalse(reg.groupHasPermission("testgroup", "first.second.third"));
        assertNull(reg.getGroupPermissionArg("testgroup", "first.second.third"));
        assertFalse(reg.groupExtendsFromGroup("testgroup", "thedefaultgroup"));
    }
    //endregion
    //endregion
}
