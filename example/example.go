package main

import (
    "fmt"
    "github.com/kunlun-qilian/jwt"
    "time"
)

func main() {
    jwtProvider := jwt.JWKSProvider{
        PrivateKey: `LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBbGpoN3ZQWWhzR1Ywa3NVMXRhV2VLSWxIc1phSTYvbjdDNStYTzJ5TVBEenpQaVdCCllWKy94UFdwQ253eVdVdDVoWk5samJxVTV5MlR3SHM3OXRJaHpyay9zalBSck5PSjE3cVpoK3pTcUF4NFZCK3AKc3ZYR2lYVytOZTRBc3UwU09zamhVZGJhR3NEVWppY21UTVlyeHlpNytZZm16UkFJTDluY0wrREZ0UWpEUVh0ZwpObUhHMVU2MUNlbW5tdHhDdzZYQkdMSHUwd01oblJ5dlFlSlhOOW1tQ0JZYnNjSTNUQ0lXeXRoYWtVenJIdFVyCm5ESlJKZG5IUngzY2ptMi9LUHdUT2xsSW1saDNRRFJOQXM4OTIzenF6R1pVTG8wb3VCcUthOUFjOWxtTXExTWMKQitkeXdCaFhnUGtHL1hmdkpqNENvYVRTUDVGTTYwcHVYdWxVK1FJREFRQUJBb0lCQUZwSDZmM2Z3dEY3dC9xNQpjUlVSU3lNN2xnM2gxYnBVaTQ4cHc3OGY5b3dCYVlMUkVaZk83cmJWbVZsRzJRK1hiNXBhd203U1VzazVPQkkzClBndVJzR1hJS2NMVXA5QUJkbGRqdXYvWTBhWFRrTUdtSWR2L0grbmZESWptMkI2d29nTVlWV3BWQU5HUlVHMTYKaytjU05wOUVHT3pYdzFzOHBsN3p4UVExUnowTDhtSnAyTEwxSEJ5UnlmbDRJVDIvYzIwNTFlWWFKY3hUamFubgpIMlpjNWxFT3dtN0NMcWk2NWNRVE1IZW5zMzdTOHBPOFVxVXU5SDN2NzZpcGs0L21ZRUJMdC8rRUs3N0ExbU1hCjBXQ0ZXaDNXOG5HVExyM3M1aGNDWVVwOEY2Z1k1MDkyeGFvV3J5Nncwdnh5YkdpNGM2QjZzNVczOWdkNGtHTmYKb1BURUlURUNnWUVBeUFDclQraGxsNjVqZWpaR2Y4eTJJajVONGE4MVg2Q3JjUlFMZXBwRWpHM3lVRHhFZHhyMwp5REw5am1HUFUxOXpQeWNsaWhJMzV0UHdsbFUvRGRpSHNucHNJR3RRWmJMa0tER25TbzV0UWtJaC9vRzM5U3NKCjNZcmhPVkVFeUVnY3ZNK0N1Q2ZBb0xmcW5jNWl6WFZ1WlQ4RU5sUi9Sby94OS85dlk4NUZWSFVDZ1lFQXdFZW4Kdy9Fb3NXdFNSV0ZoUy83eGgvVXNmSzFMOFdWb1hIUWJmSENUWlJWSGNyajQrYy83MGo1T3lJU1ZIK0IzUUltZgpVOWlNUzJvL3lCVXdDMm5zMVlxV1VQRGxoVEY3SnVpOXhEbWx4cXZubGUyVlROTytPMlBEK2p0WGdCakUya0Z3CiswanFvZCs1bXdMZUJ0Mno5bTEzYlVtUmZpVUFYWUg0YmlzOVhmVUNnWUVBbGJtYWhobXVaRjBTNzV6T0xrSnMKWHpwUlI1REkzaXdEN0lWYkNvK09uYXA1YW9PVHBhNjByRlV2NkhVMHZPK0o4VTgzRlNRS1lXMXNnTDZVazZMMApBek1PMno0N1U4Y1djdGlwS25GeGJkYmdhQTFvVDh2R2VPbk5MZ0Z2R1JpVEd1NG1LQUxxZStielp1dm9uM000CkQrZWJHYWtzRndFUDNkNkYzeXUrVHprQ2dZQTQ1RHE0V0IrQk4wNzFabFhDaGFGelo5Q001ejJrSkN3WHh1Ym4KRCt3Y3FZb2xZS09TVHI2a3UzaldEWnlOL1AxcjVBeDNZNGhIUEIyNUZzUExiTUQ5Z2U3dDdna0xPdFBFZEhMSgpuNEQwWXFLNEVyN3RKMjJPNXZyeWpDSmNyWGQ1V0ltVVlFUEVONDBVVjJuWVFEcmlQQXR0RTZwdjE0VGZKZmlhCnFFS1ZEUUtCZ0RuNktnSEU2NmY2VmR3UjFYN3R2WkVSOUo5d1pUWmJCZHpLZm81OWs4M0lRUXRFY0dxbnM2N0kKaXRuM1NZR3htUk5La2VzazNBQ2pKbTNEZyszTjNxakYrZjR1MTMyMmNTc3JCc2dQUEZIMGtwcGlyQS9tNmsvagowdmxBU1ZBa05WbHpZM3RONXJxRWtER2RFL21PNnE2ZlhMUkZkY201RGh2TzcwcHdhOUNhCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==`,
        PublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAljh7vPYhsGV0ksU1taWe
KIlHsZaI6/n7C5+XO2yMPDzzPiWBYV+/xPWpCnwyWUt5hZNljbqU5y2TwHs79tIh
zrk/sjPRrNOJ17qZh+zSqAx4VB+psvXGiXW+Ne4Asu0SOsjhUdbaGsDUjicmTMYr
xyi7+YfmzRAIL9ncL+DFtQjDQXtgNmHG1U61CemnmtxCw6XBGLHu0wMhnRyvQeJX
N9mmCBYbscI3TCIWythakUzrHtUrnDJRJdnHRx3cjm2/KPwTOllImlh3QDRNAs89
23zqzGZULo0ouBqKa9Ac9lmMq1McB+dywBhXgPkG/XfvJj4CoaTSP5FM60puXulU
+QIDAQAB
-----END PUBLIC KEY-----`,
    }

    jwtProvider.Init()

    ValidToken(&jwtProvider)
    InvalidToken(&jwtProvider)
    ExpiredToken(&jwtProvider)

}

func ValidToken(jwtProvider *jwt.JWKSProvider) {
    mgr := jwt.NewJwtMgr(jwtProvider, true)
    tokenByte, _ := mgr.SignToken("test-client", "jwt provider", "jwt provider", time.Now().Add(time.Hour*24), nil)
    auth := jwt.Authorizations{}
    auth.Add("Bearer", string(tokenByte))
    token := auth.String()
    fmt.Println("token: ", token)

    // 校验token
    t, err := mgr.ValidateTokenByTokenKey("Bearer", token)
    if err != nil {
        panic(err)
    }
    // 获取token Audience
    fmt.Println(t.Audience())
}

func InvalidToken(jwtProvider *jwt.JWKSProvider) {
    mgr := jwt.NewJwtMgr(jwtProvider, true)
    tokenByte, _ := mgr.SignToken("test-client", "jwt provider", "jwt provider", time.Now().Add(time.Hour*24), nil)
    auth := jwt.Authorizations{}
    auth.Add("Bearer", string(tokenByte))

    token := auth.String()

    fmt.Println("token: ", token)

    // 校验token
    _, err := mgr.ValidateTokenByTokenKey("Bearer", token[2:])
    if err != nil {
        fmt.Println("error: ", err)
    }

}

func ExpiredToken(jwtProvider *jwt.JWKSProvider) {
    mgr := jwt.NewJwtMgr(jwtProvider, true)
    tokenByte, _ := mgr.SignToken("test-client", "jwt provider", "jwt provider", time.Now().Add(time.Second), nil)
    auth := jwt.Authorizations{}
    auth.Add("Bearer", string(tokenByte))

    token := auth.String()

    fmt.Println("token: ", token)

    time.Sleep(time.Second * 3)

    // 校验token
    _, err := mgr.ValidateTokenByTokenKey("Bearer", token)
    if err != nil {
        fmt.Println("error: ", err)
    }
}
