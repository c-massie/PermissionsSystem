package scot.massie.lib.permissions;

import org.junit.jupiter.api.Test;

import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

public class PermissionsRegistryTest
{
    protected PermissionsRegistry<String> getNewPermissionsRegistry()
    { return new PermissionsRegistry<>(s -> s, s -> s); }

    @Test
    public void basicTest()
    {
        PermissionsRegistry<String> reg = getNewPermissionsRegistry();

        reg.assignUserPermission("user1", "some.permission.doot");
        reg.assignUserPermission("user1", "some.other.permission");

        String expectedResult = "user1\n    some.permission.doot\n    some.other.permission";

        assertEquals(expectedResult, reg.usersToSaveString());
    }
}