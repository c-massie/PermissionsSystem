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


}
