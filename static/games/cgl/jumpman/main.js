const title = "JUMPMAN";

const description = `
 TAP TO JUMP, MAN
`;

characters = [
  `
llllll
ll l l
ll l l
llllll
 l  l
 l  l
  `,
  `
llllll
ll l l
ll l l
llllll
ll  ll
  `,
  `
  lll
ll l l
 llll
  ll
 l  l
 l  l
`,
  `
  lll
ll l l
 llll
 l  l
ll  ll
`,
  `
ll
 ll
 ll l
llllll


`,
  `

    l
llllll
 ll
 ll
ll
`,
];

const G = {
  WIDTH: 100,
  HEIGHT: 100,
  STAR_SPEED_MIN: 0.5,
  STAR_SPEED_MAX: 1.0,
  STAR_HEIGHT: 80,
  GRAVITY: vec(0, 0.17),
};

const options = {
  isPlayingBgm: true,
  viewSize: { x: G.WIDTH, y: G.HEIGHT },
  theme: "pixel",
  seed: 6 * 12,
};

let obstacles;
let coins;
let stars;
let animationTicks;
let obstacleTicks;
let coinTicks;

/** @type {{
      position: Vector,
      velocity: Vector,
      currentAnimation: string,
      isJumping: bool
      gravity: Vector,
      color: Color,
    }}
 */
let player;

function update() {
  if (!ticks) {
    G.OBJECT_VELOCITY = 0.5 * difficulty;

    player = {
      position: vec(15, 90),
      velocity: vec(),
      currentAnimation: "a",
      isJumping: false,
      color: "cyan",
    };

    // Initialize the stars.
    stars = times(20, () => {
      const x = rnd(0, G.WIDTH);
      const y = rnd(0, G.STAR_HEIGHT);
      const position = vec(x, y);

      return {
        position,
        velocity: rnd(G.STAR_SPEED_MIN, G.STAR_SPEED_MAX) * difficulty,
        draw: () => {
          color("black");
          box(position, 1);
        },
      };
    });

    obstacles = [];
    coins = [];
    animationTicks = 0;
    obstacleTicks = 0;
    coinTicks = 0;
  }

  obstacleTicks--;
  coinTicks--;

  if (obstacleTicks < 1) {
    obstacleTicks = rndi(130, 180) - difficulty * 5;

    const height = rndi(10 + floor(difficulty * 2), 23 + floor(difficulty * 2));
    const width = rndi(5 + floor(difficulty * 2), 10 + floor(difficulty * 2));

    const obstacle = {
      position: vec(G.WIDTH + 5, 95 - height),
      velocity: vec(G.OBJECT_VELOCITY, 0),
      draw: () => {
        color("light_black");
        return rect(obstacle.position, width, height);
      },
    };

    obstacles.push(obstacle);
  }

  if (coinTicks < 1) {
    coinTicks = 35 - difficulty * 4;

    const coin = {
      position: vec(G.WIDTH + 5, 87),
      velocity: vec(G.OBJECT_VELOCITY, 0),
      isCollected: false,
      draw: () => {
        color("yellow");
        return box(coin.position, 5);
      },
    };

    coins.push(coin);
  }

  if (!player.isJumping && input.isJustPressed) {
    player.velocity.sub(vec(0, 5));
    player.isJumping = true;
    play("jump");
  }

  const df = sqrt(difficulty);
  animationTicks += df;

  player.velocity.add(G.GRAVITY);
  player.position.add(player.velocity);

  if (player.position.y > 93) {
    player.position.y = 93;
    player.velocity = vec();
    player.isJumping = false;
  }

  // Draw the stars in the background.
  stars.forEach(star => {
    star.position.x -= star.velocity;
    star.position.wrap(0, G.WIDTH, 0, G.STAR_HEIGHT);
    star.draw();
  });

  // Draw the floor.
  color("light_black");
  line(0, G.HEIGHT, G.WIDTH, G.HEIGHT, 15);

  // Make player update.
  const currentAnimation = addWithCharCode("a", floor(animationTicks / 15) % 2);

  // Draw the player.
  color("cyan");
  char(currentAnimation, player.position.x + 3, player.position.y - 3);

  // Draw the obstacles and check for collision with the player.
  obstacles.forEach(obstacle => {
    obstacle.position.sub(obstacle.velocity);

    if (obstacle.draw().isColliding.char[currentAnimation]) end();
  });

  // Draw the coins and check for collision with the player and the obstacles.
  // Checking for obstacle collision is necessary so that both don't overlap.
  coins.forEach(coin => {
    coin.position.sub(coin.velocity);

    const coinCollision = coin.draw();

    if (coinCollision.isColliding.char[currentAnimation]) {
      play("coin");
      addScore(1, vec(coin.position.x, coin.position.y + 10));
      particle(vec(coin.position.x, coin.position.y + 3), 50, 2);
      coin.isCollected = true;
    } else if (coinCollision.isColliding.rect.light_black) {
      coin.isCollected = true;
    }
  });

  remove(obstacles, obstacle => obstacle.position.x < -10);
  remove(coins, coin => coin.isCollected || coin.position.x < -5);
}
