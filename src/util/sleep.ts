export const sleep = (period: number) => {
  return new Promise((resolve) => setTimeout(resolve, period));
};
