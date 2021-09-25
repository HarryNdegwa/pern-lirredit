import { Entity, PrimaryKey, Property } from "@mikro-orm/core";
import { Field, ObjectType } from "type-graphql";

@ObjectType()
@Entity()
export class User {
  @Field()
  @PrimaryKey()
  id!: number;

  @Field()
  @Property({ unique: true })
  username!: string;

  @Field()
  @Property({ unique: true, nullable: true })
  email: string;

  @Property()
  password!: string;

  @Field()
  @Property({ type: "date" })
  createdAt: Date = new Date();

  @Field() // Exposes this field in the schema
  @Property({ onUpdate: () => new Date() })
  updatedAt: Date = new Date();
}
