package scot.massie.lib.permissions;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;
import scot.massie.lib.utils.wrappers.MutableWrapper;

import java.io.IOException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PermissionsRegistryTest
{
    /*

    Note: Tests that pass for users are expected to pass for groups as well, as they're both implemented using the same
    class. Providing test coverage for both would be needless duplication.

     */

    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new PermissionsRegistry<>(s -> s, s -> s); }



    //region Method tests
    //region Assertions
    //region Permissions
    //region Has

    // For anything beyond simple "has" or "doesn't have", behvaiour is expected to be comparable to the regular "has
    // permission" methods. So tests are only provided for "has" and "doesn't have".
    @Test
    void assertHasPermission_has()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertDoesNotThrow(() -> reg.assertUserHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    void assertHasPermission_doesntHave()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        MutableWrapper<UserMissingPermissionException> exceptionThrownWrapper = new MutableWrapper<>(null);
        UserMissingPermissionException exceptionThrown;

        assertThatThrownBy(() -> reg.assertUserHasPermission("user1", "some.permission.foot"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .matches(ex -> { exceptionThrownWrapper.set(ex); return true; });

        exceptionThrown = exceptionThrownWrapper.get();

        assertThat(exceptionThrown.getUserId()).isEqualTo("user1");
        assertThat(exceptionThrown.getPermissions()).containsExactly("some.permission.foot");
        assertThat(exceptionThrown.multiplePermissionsWereMissing()).isFalse();
        assertThat(exceptionThrown.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue();
        assertThat(exceptionThrown.getPermission()).isEqualTo("some.permission.foot");
    }
    //endregion

    //region Has all
    @Test
    void assertHasAllPermissions_hasNone()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");

        MutableWrapper<UserMissingPermissionException> exceptionThrownWrapper = new MutableWrapper<>(null);
        UserMissingPermissionException exceptionThrown;

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .matches(ex -> { exceptionThrownWrapper.set(ex); return true; });

        exceptionThrown = exceptionThrownWrapper.get();

        assertThat(exceptionThrown.getUserId()).isEqualTo("user1");
        assertThat(exceptionThrown.getPermissions()).containsExactlyInAnyOrder("some",
                                                                               "some.permission.doot",
                                                                               "some.permission.hoot",
                                                                               "some.other.permission");
        assertThat(exceptionThrown.multiplePermissionsWereMissing()).isTrue();
        assertThat(exceptionThrown.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse();
    }

    @Test
    void assertHasAllPermissions_hasNoneOfOne()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");

        MutableWrapper<UserMissingPermissionException> exceptionThrownWrapper = new MutableWrapper<>(null);
        UserMissingPermissionException exceptionThrown;

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1", "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .matches(ex -> { exceptionThrownWrapper.set(ex); return true; });

        exceptionThrown = exceptionThrownWrapper.get();

        assertThat(exceptionThrown.getUserId()).isEqualTo("user1");
        assertThat(exceptionThrown.getPermissions()).containsExactly("some.other.permission");
        assertThat(exceptionThrown.multiplePermissionsWereMissing()).isFalse();
        assertThat(exceptionThrown.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue();
        assertThat(exceptionThrown.getPermission()).isEqualTo("some.other.permission");
    }

    @Test
    void assertHasAllPermissions_hasOneOfMultiple()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");

        MutableWrapper<UserMissingPermissionException> exceptionThrownWrapper = new MutableWrapper<>(null);
        UserMissingPermissionException exceptionThrown;

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .matches(ex -> { exceptionThrownWrapper.set(ex); return true; });

        exceptionThrown = exceptionThrownWrapper.get();

        assertThat(exceptionThrown.getUserId()).isEqualTo("user1");
        assertThat(exceptionThrown.getPermissions()).containsExactlyInAnyOrder("some",
                                                                               "some.permission.doot",
                                                                               "some.other.permission");
        assertThat(exceptionThrown.multiplePermissionsWereMissing()).isTrue();
        assertThat(exceptionThrown.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse();
    }

    @Test
    void assertHasAllPermissions_hasSome()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        MutableWrapper<UserMissingPermissionException> exceptionThrownWrapper = new MutableWrapper<>(null);
        UserMissingPermissionException exceptionThrown;

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .matches(ex -> { exceptionThrownWrapper.set(ex); return true; });

        exceptionThrown = exceptionThrownWrapper.get();

        assertThat(exceptionThrown.getUserId()).isEqualTo("user1");
        assertThat(exceptionThrown.getPermissions()).containsExactlyInAnyOrder("some",
                                                                               "some.permission.doot");
        assertThat(exceptionThrown.multiplePermissionsWereMissing()).isTrue();
        assertThat(exceptionThrown.anySinglePermissionWouldHavePassedPermissionCheck()).isFalse();
    }

    @Test
    void assertHasAllPermissions_hasAllButOne()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.irrelevant.permissions");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        MutableWrapper<UserMissingPermissionException> exceptionThrownWrapper = new MutableWrapper<>(null);
        UserMissingPermissionException exceptionThrown;

        assertThatThrownBy(() -> reg.assertUserHasAllPermissions("user1",
                                                                 "some.permission.doot",
                                                                 "some.permission.hoot",
                                                                 "some.other.permission"))
                .isInstanceOf(UserMissingPermissionException.class)
                .asInstanceOf(InstanceOfAssertFactories.type(UserMissingPermissionException.class))
                .matches(ex -> { exceptionThrownWrapper.set(ex); return true; });

        exceptionThrown = exceptionThrownWrapper.get();

        assertThat(exceptionThrown.getUserId()).isEqualTo("user1");
        assertThat(exceptionThrown.getPermissions()).containsExactly("some", "some.permission.doot");
        assertThat(exceptionThrown.multiplePermissionsWereMissing()).isFalse();
        assertThat(exceptionThrown.anySinglePermissionWouldHavePassedPermissionCheck()).isTrue();
        assertThat(exceptionThrown.getPermission()).isEqualTo("some.permission.doot");
    }

    @Test
    void assertHasAllPermissions_hasAll()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void assertHasAnyPermissions_hasSome()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void assertHasAnyPermissions_hasAll()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
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
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_doesNotHave_hasSubpermission()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_doesNotHave_hasAllSubpermissionsViaWildcard()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasDirectlyExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasDirectlyUnderOtherWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasDirectlyUnderWildcardWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasDirectlyExactlyWithArg_hasDirectlyUnderOtherWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasViaGroupExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasViaGroupsGroupWxactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasViaDefaultsExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_hasViaDefaultGroupExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_negatedDirectlyExactly_hasViaGroupExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_negatedDirectlyExactly_hasViaDefaultsExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_negatedViaGroupExactly_hasViaGroupsGroupExactly()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_negatedViaGroupExactly_hasViaHigherPriorityGroupExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_negatedViaGroupExactly_hasViaLowerPriorityGroupExactlyWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_negatedDirectlySubpermission_hasDirectlySuperpermissionWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    public void getPermissionStatus_negatedDirectlyCoveringWildcard_hasDirectlySameButNotWildcardWithArg()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    //endregion

    //region Multiple

    //endregion
    //endregion

    //region Has
    //region Normally
    @Test
    public void hasPermission_none()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.shoot"));
    }

    @Test
    public void hasPermission_exact()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_atWildcard()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_underExact()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot.likeanowl"));
    }

    @Test
    public void hasPermission_underWildcard()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot.likeanowl"));
    }

    @Test
    public void hasPermission_overExact()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission"));
    }

    @Test
    public void hasPermission_overWildcard()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission"));
    }

    @Test
    public void hasPermission_root()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", ""));
    }

    @Test
    public void hasPermission_atUniversal()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "*");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", ""));
    }

    @Test
    public void hasPermission_underUniversal()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "*");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "a.completely.different.perm"));
    }

    @Test
    public void hasPermission_negatedRedundantly_exact()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "-some.permission.hoot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_negated_exact()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot.noot"));
    }

    @Test
    public void hasPermission_negated_atWildcard()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot.noot"));
    }

    @Test
    public void hasPermission_negated_underExact()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot.noot.joot"));
    }

    @Test
    public void hasPermission_negated_underWildcard()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        assertFalse(reg.userHasPermission("user1", "some.permission.hoot.noot.joot"));
    }

    @Test
    public void hasPermission_negated_overExact()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.permission.hoot");
        reg.assignUserPermission("user1", "-some.permission.hoot.noot");
        reg.assignUserPermission("user1", "some.other.permission");

        assertTrue(reg.userHasPermission("user1", "some.permission.hoot"));
    }

    @Test
    public void hasPermission_negated_overWildcard()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllPermissions_hasSome()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllPermissions_hasAllDirectly()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllPermissions_hasSomeDirectly_restViaGroups()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllPermissions_hasSomeDirectly_restViaDefaults()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllPermissions_hasSomeDirectly_restViaSuperpermissions()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    //endregion

    //region Has any

    @Test
    void hasAnyPermissions_hasNone()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyPermissions_hasSome()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyPermissions_hasAll()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyPermissions_hasSomeViaGroups()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyPermissions_hasSomeViaDefaults()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyPermissions_hasSomeViaSuperpermissions()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    //endregion

    //region Has any subpermission of
    @Test
    public void hasAnySubPermissionOf_none()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        assertFalse(reg.userHasAnySubPermissionOf("user1", "my.perm"));
    }

    @Test
    public void hasAnySubPermissionOf_direct()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "my.perm");

        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm.here"));
    }

    @Test
    public void hasAnySubPermissionOf_inherited()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignGroupToUser("user1", "group1");
        reg.assignGroupPermission("group1", "my.perm");

        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my"));
        assertTrue(reg.userHasAnySubPermissionOf("user1", "my.perm.here"));
    }

    @Test
    public void hasAnySubPermissionOf_negatedSame()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin: doot");

        assertEquals("doot", reg.getUserPermissionArg("user1", "europe.germany.berlin"));
    }

    @Test
    public void getUserPermissionArg_empty()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin:");

        assertEquals("", reg.getUserPermissionArg("user1", "europe.germany.berlin"));
    }

    @Test
    public void getUserPermissionArg_noArg()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        assertNull(reg.getUserPermissionArg("user1", "europe.germany.berlin"));
    }

    @Test
    public void getUserPermissionArg_noPermission()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "europe.austria.vienna");
        reg.assignUserPermission("user1", "europe.germany.berlin");

        assertNull(reg.getUserPermissionArg("user1", "europe.poland.warsaw"));
    }

    @Test
    public void getUserPermissionArg_universal()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignGroupToGroup("red", "blue");
        reg.assignGroupToGroup("green", "red");
        reg.assignGroupToGroup("cyan", "green");
        reg.getGroupPermissionsGroupOrNew("yellow");
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
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllGroups_some()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllGroups_all()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllGroups_allViaOtherGroups()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAllGroups_allViaDefaults()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    //endregion

    //region Has any

    @Test
    void hasAnyGroups_none()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyGroups_some()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyGroups_someViaOtherGroups()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyGroups_someViaDefaults()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void hasAnyGroups_all()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    //endregion
    //endregion

    //region State

    //endregion

    //region Getters
    //region Members
    //endregion

    //region Permissions
    @Test
    public void getUsers_empty()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        assertThat(reg.getUsers()).isEmpty();
    }

    @Test
    public void getUsers()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("userdoot", "my.first.perm");
        reg.assignUserPermission("userhoot", "my.second.perm");
        reg.assignUserPermission("usernoot", "my.third.perm");

        assertThat(reg.getUsers())
                .containsExactlyInAnyOrderElementsOf(Arrays.asList("userdoot", "userhoot", "usernoot"));
    }
    //endregion

    //region Permissions and statuses

    @Test
    void getPermissionsAndStatuses_userDoesntExist()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void getPermissionsAndStatuses_userHasNone()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void getPermissionsAndStatuses_userHasSomeDirectly()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void getPermissionsAndStatuses_userHasSomeViaGroup()
    {
        // This method shouldn't include permissions a user has indirectly.

        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void getPermissionsAndStatuses_userHasSomeViaDefaults()
    {
        // This method shouldn't include permissions a user has indirectly.

        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    //endregion

    //region Groups
    @Test
    public void getGroupNames_empty()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        assertThat(reg.getGroupNames()).isEmpty();
    }

    @Test
    public void getGroupNames()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        assertThat(reg.getUserPermissions("nonexistentuser")).isEmpty();
    }

    @Test
    public void getPermissions()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
    //region Permissions
    //region Assign
    @Test
    public void assignPermission()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    some.other.permission\n    some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_negating()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "-some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    some.other.permission\n    -some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_wildcard()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot.*");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    some.other.permission\n    some.permission.doot.*";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_universal()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "*");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    *\n    some.other.permission\n    some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermission_universalNegating()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "-*");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    -*\n    some.other.permission\n    some.permission.doot";
        assertEquals(expectedResult, reg.usersToSaveString());
    }

    @Test
    public void assignPermissionToGroup()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignGroupPermission("group1", "some.permission.doot");
        reg.assignGroupPermission("group1", "some.other.permission");

        String expectedResult = "group1\n    some.other.permission\n    some.permission.doot";
        assertEquals("", reg.usersToSaveString());
        assertEquals(expectedResult, reg.groupsToSaveString());
    }
    //endregion

    //region Revoke
    @Test
    public void revokePermission()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
    @Test
    public void assignGroupToUser()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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

    //region Revoke
    @Test
    void revokeGroupFromUser_had()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void revokeGroupFromUser_didntHave()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void revokeGroupFromGroup_had()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void revokeGroupFromGroup_didntHave()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }
    //endregion
    //endregion

    //region Clear

    @Test
    void clear_empty()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void clear_onlyHadUsers()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void clear_onlyHadGroups()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void clear_onlyHadDefaults()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
    }

    @Test
    void clear_hadUsersGroupsAndDefaults()
    {
        // TO DO: Write.
        System.out.println("Test not yet written.");
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();

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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();

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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.getGroupPermissionsGroupOrNew("katara", 5);
        reg.getGroupPermissionsGroupOrNew("iroh", -3.76);
        reg.getGroupPermissionsGroupOrNew("azula", -3.4);
        reg.getGroupPermissionsGroupOrNew("suki", -3.9);
        reg.getGroupPermissionsGroupOrNew("appa", -3);
        reg.getGroupPermissionsGroupOrNew("momo", -4);
        reg.getGroupPermissionsGroupOrNew("jet", 4.2);
        reg.getGroupPermissionsGroupOrNew("sozin", 2.5);

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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.getGroupPermissionsGroupOrNew("katara", 5);
        reg.getGroupPermissionsGroupOrNew("iroh", -3.76);
        reg.getGroupPermissionsGroupOrNew("azula", -3.4);
        reg.getGroupPermissionsGroupOrNew("suki", -3.9);
        reg.getGroupPermissionsGroupOrNew("appa", -3);
        reg.getGroupPermissionsGroupOrNew("momo", -4);
        reg.getGroupPermissionsGroupOrNew("jet", 4.2);
        reg.getGroupPermissionsGroupOrNew("sozin", 2.5);

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

        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.getGroupPermissionsGroupOrNew("katara");
        reg.getGroupPermissionsGroupOrNew("iroh");
        reg.getGroupPermissionsGroupOrNew("azula");
        reg.getGroupPermissionsGroupOrNew("suki");
        reg.getGroupPermissionsGroupOrNew("appa");
        reg.getGroupPermissionsGroupOrNew("momo");
        reg.getGroupPermissionsGroupOrNew("jet");
        reg.getGroupPermissionsGroupOrNew("sozin");
        reg.getGroupPermissionsGroupOrNew("toph", 2);
        reg.getGroupPermissionsGroupOrNew("boulder", 2);

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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("this.is.a.permission");
        assertTrue(reg.userHasPermission("toodles", "this.is.a.permission.too"));
    }

    @Test
    public void defaultPermissions_fallingBack_onExistingUser()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("this.is.a.permission: 5");
        reg.assignDefaultPermission("this.is.another.permission: 6");
        reg.assignUserPermission("toodles", "this.is.a: 7");
        assertEquals("7", reg.getUserPermissionArg("toodles", "this.is.a.permission"));
        assertEquals("6", reg.getUserPermissionArg("toodles", "this.is.another.permission"));
    }

    @Test
    public void defaultPermissions_fallingBack_toDefaultGroup()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
        reg.assignDefaultPermission("first.second.third: doot");
        reg.assignDefaultGroup("thedefaultgroup");

        assertFalse(reg.groupHasPermission("testgroup", "first.second.third"));
        assertNull(reg.getGroupPermissionArg("testgroup", "first.second.third"));
        assertFalse(reg.groupExtendsFromGroup("testgroup", "thedefaultgroup"));
    }

    @Test
    public void defaultPermissions_group_existing()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();
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
