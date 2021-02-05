package scot.massie.lib.permissions;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

public class PermissionsRegistryTest
{
    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new PermissionsRegistry<>(s -> s, s -> s); }

    //region assignPermission
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

    //region hasPermission
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

    //region assignGroups
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

    //region hasPermissionViaGroup
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
        reg.assignGroupPermission("-group1", "europe.france.paris");
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
        reg.assignGroupPermission("-group1", "europe.france.paris");
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
}
