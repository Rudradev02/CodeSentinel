import React, { useEffect, useState } from "react";
import { Button } from "./components/Button";
import { fetchUsers, UserDto } from "./utils/api";

export default function App() {
  const [users, setUsers] = useState<UserDto[]>([]);

  useEffect(() => {
    fetchUsers().then(setUsers);
  }, []);

  return (
    <div>
      <h1>Sample App</h1>
      <Button label="Click Me" />
      <ul>
        {users.map((u) => (
          <li key={u.id}>{u.name}</li>
        ))}
      </ul>
    </div>
  );
}
