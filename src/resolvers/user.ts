import { MyContext } from "src/types";
import {
  Arg,
  Ctx,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Resolver,
} from "type-graphql";
import { User } from "../entities/User";
import argon2 from "argon2";

@InputType()
class UsernamePasswordInput {
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
  //   @Query(() => [Post])
  //   posts(@Ctx() ctx: MyContext): Promise<Post[]> {
  //     return ctx.em.find(Post, {});
  //   }

  //   @Query(() => Post, { nullable: true })
  //   post(
  //     @Arg("id", () => Int) id: number,
  //     @Ctx() ctx: MyContext
  //   ): Promise<Post | null> {
  //     return ctx.em.findOne(Post, { id });
  //   }

  @Mutation(() => UserResponse)
  async register(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() ctx: MyContext
  ): Promise<UserResponse> {
    if (options.username.length < 2) {
      return {
        errors: [
          { field: "username", message: "username should be 2+ characters" },
        ],
      };
    }
    const hashedPassword = await argon2.hash(options.password);
    const user = ctx.em.create(User, {
      username: options.username,
      password: hashedPassword,
    });
    try {
      await ctx.em.persistAndFlush(user);
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
    return { user };
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() ctx: MyContext
  ): Promise<UserResponse> {
    const user = await ctx.em.findOne(User, {
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

    console.log(`isPasswordValid`, isPasswordValid);

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

    return { user };
  }

  //   @Mutation(() => Post, { nullable: true })
  //   async updatePost(
  //     @Arg("id") id: number,
  //     @Arg("title") title: string,
  //     @Ctx() ctx: MyContext
  //   ): Promise<Post | null> {
  //     const post = await ctx.em.findOne(Post, { id });
  //     if (!post) {
  //       return null;
  //     }

  //     if (title) {
  //       post.title = title;
  //       await ctx.em.persistAndFlush(post);
  //     }

  //     return post;
  //   }

  //   @Mutation(() => Boolean)
  //   async deletePost(@Arg("id") id: number, @Ctx() ctx: MyContext) {
  //     await ctx.em.nativeDelete(Post, { id });
  //     return true;
  //   }
}
