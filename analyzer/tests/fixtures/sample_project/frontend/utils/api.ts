export interface UserDto {
  id: number;
  name: string;
}

export async function fetchUsers(): Promise<UserDto[]> {
  return [
    { id: 1, name: "Alice" },
    { id: 2, name: "Bob" },
  ];
}
