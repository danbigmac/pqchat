#include <iostream>

#include "pqchat/client/client.h"
#include "pqchat/server/in_memory_server.h"

int main() {
  using pqchat::client::Client;
  using pqchat::server::InMemoryServer;

  InMemoryServer server;

  auto alice_result = Client::Create("alice");
  auto bob_result = Client::Create("bob");
  if (!alice_result.ok() || !bob_result.ok()) {
    std::cerr << "client create failed\n";
    return 1;
  }

  auto alice = alice_result.take_value();
  auto bob = bob_result.take_value();

  if (!alice.PublishPrekeys(&server).ok() || !bob.PublishPrekeys(&server).ok()) {
    std::cerr << "prekey publish failed\n";
    return 1;
  }

  auto init = alice.InitiateSession(&server, "bob", "hello from alice");
  if (!init.ok()) {
    std::cerr << "init failed: " << init.error() << "\n";
    return 1;
  }

  auto bob_msgs = bob.ProcessInbox(&server);
  if (!bob_msgs.ok()) {
    std::cerr << "bob inbox failed: " << bob_msgs.error() << "\n";
    return 1;
  }

  for (const auto& msg : bob_msgs.value()) {
    std::cout << "bob received: " << msg << "\n";
  }

  auto reply = bob.SendMessage(&server, "alice", "hello from bob");
  if (!reply.ok()) {
    std::cerr << "reply failed: " << reply.error() << "\n";
    return 1;
  }

  auto alice_msgs = alice.ProcessInbox(&server);
  if (!alice_msgs.ok()) {
    std::cerr << "alice inbox failed: " << alice_msgs.error() << "\n";
    return 1;
  }

  for (const auto& msg : alice_msgs.value()) {
    std::cout << "alice received: " << msg << "\n";
  }

  return 0;
}
