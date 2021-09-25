import { MyContext } from "src/types";
import {
  Arg,
  Ctx,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Resolver,
  Query,
} from "type-graphql";
import { User } from "../entities/User";
import argon2 from "argon2";
import { COOKIE_NAME } from "../constants";

@InputType()
class RegisterInput {
  @Field()
  username: string;

  @Field()
  email?: string;

  @Field()
  password: string;
}

@InputType()
class LoginInput {
  @Field()
  username: string;

  @Field()
  password: string;
}

@ObjectType()
class FieldError {
  @Field()
  field: string;

  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;
}

@Resolver()
export class UserResolver {
  @Query(() => User, { nullable: true })
  async me(@Ctx() { em, req }: MyContext) {
    if (!req.session.UserID) {
      return null;
    }
    const user = await em.findOne(User, { id: req.session.UserID });
    return user;
  }

  @Mutation(() => UserResponse)
  async register(
    @Arg("options") options: RegisterInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    if (options.username.length < 2) {
      return {
        errors: [
          { field: "username", message: "username should be 2+ characters" },
        ],
      };
    }

    if (!options.email?.includes("@")) {
      return {
        errors: [{ field: "email", message: "Invalid email" }],
      };
    }
    const hashedPassword = await argon2.hash(options.password);
    const user = em.create(User, {
      username: options.username,
      email: options.email,
      password: hashedPassword,
    });
    try {
      await em.persistAndFlush(user);
    } catch (error) {
      console.log(`error`, error.message);
      if (error.detail.includes("already exists")) {
        return {
          errors: [
            {
              field: "username",
              message: "Username already exists!",
            },
          ],
        };
      }
    }

    req.session.UserID = user.id;

    return { user };
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("options") options: LoginInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(User, {
      username: options.username,
    });

    if (!user) {
      return {
        errors: [
          {
            field: "username",
            message: "User does not exist!",
          },
        ],
      };
    }

    const isPasswordValid = await argon2.verify(
      user.password,
      options.password
    );

    if (!isPasswordValid) {
      return {
        errors: [
          {
            field: "password",
            message: "Invalid password!",
          },
        ],
      };
    }

    req.session.UserID = user.id;

    return { user };
  }

  @Mutation(() => Boolean)
  logout(@Ctx() { req, res }: MyContext) {
    return new Promise((resolve) =>
      req.session.destroy((err) => {
        if (err) {
          console.log(`err`, err);
          resolve(false);
          return;
        }

        res.clearCookie(COOKIE_NAME);
        resolve(true);
      })
    );
  }

  // @Mutation(() => Boolean)
  // async forgotPassword(
  //   @Arg("email") email: string,
  //   @Ctx() { em, req }: MyContext
  // ) {
  //   // const user = await em.findOne(User,{email})
  //   return true;
  // }
}
