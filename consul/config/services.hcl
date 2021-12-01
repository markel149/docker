

service {
  name = "prueba1"
  address = "192.0.2.10"
  port = 80
  tagged_addresses {
    virtual = {
      address = "203.0.113.50"
      port = 80
    }
  }
}
