package de.gghub.keycloak.steam;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SteamProfileAttributeMapperTest {
    @Test void importsVerifiedSteamIdIntoSelectedCustomAttribute() {
        var config=new IdentityProviderModel();config.setEnabled(true);
        var context=new BrokeredIdentityContext(SteamAssertionTest.STEAM_ID,config);
        context.getContextData().put(SteamProfileAttributeMapper.CONTEXT_JSON_NODE,
            JsonNodeFactory.instance.objectNode().put("steam_id",SteamAssertionTest.STEAM_ID));
        var model=new IdentityProviderMapperModel();
        model.setConfig(new HashMap<>(Map.of("jsonField","steam_id","userAttribute","steamId")));
        var mapper=new SteamProfileAttributeMapper();
        mapper.preprocessFederatedIdentity(null,null,model,context);
        assertEquals(SteamAssertionTest.STEAM_ID,context.getUserAttribute("steamId"));
        var user=mock(UserModel.class);
        mapper.updateBrokeredUser(null,null,user,model,context);
        verify(user).setSingleAttribute("steamId",SteamAssertionTest.STEAM_ID);
        assertTrue(mapper.getConfigProperties().stream().anyMatch(p -> p.getName().equals("userAttribute") && p.getType().equals(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE)));
    }
}
